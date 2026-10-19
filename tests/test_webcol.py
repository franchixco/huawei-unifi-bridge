import asyncio
import atexit
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

WEBROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('webcol_under_test', WEBROOT / 'webcol' / 'webcol.py')
webcol = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(webcol)

# Keep every test's registry write inside a throwaway directory.
_STATE_TMP = tempfile.TemporaryDirectory(prefix='webcol-test-')
atexit.register(_STATE_TMP.cleanup)
webcol.INVENTORY_STATE_FILE = os.path.join(_STATE_TMP.name, 'inventory_state.json')


def result_entry(clients=(), ssids=()):
    return {'ok': True, 'clients': list(clients), 'ssids': list(ssids), 'version': 'test'}


def patch_direct_transport(testcase, results):
    """Replace the direct API transport with canned per-host outcomes.

    Cycle tests must never open real connections to the configured router
    addresses (a real wrong-password login attempt is exactly what the
    lockout policy forbids).
    """
    outcomes = dict(results)

    async def fake_direct(collector_self, host, password):
        outcome = outcomes.get(host)
        if isinstance(outcome, Exception):
            raise outcome
        if outcome is None:
            return {'ok': False, 'stage': 'wifi-schema', 'transport': 'direct'}
        return outcome

    patcher = unittest.mock.patch.object(webcol.Collector, 'collect_direct', fake_direct)
    patcher.start()
    testcase.addCleanup(patcher.stop)
    return outcomes


def _booming_method(message):
    async def boom(self):
        raise AssertionError(message)
    return boom


def isolate_inventory_state(testcase):
    directory = tempfile.TemporaryDirectory()
    testcase.addCleanup(directory.cleanup)
    path = os.path.join(directory.name, 'inventory_state.json')
    patcher = unittest.mock.patch.object(webcol, 'INVENTORY_STATE_FILE', path)
    patcher.start()
    testcase.addCleanup(patcher.stop)
    return path


class RouterConfigTests(unittest.TestCase):
    def test_parse_and_skip_invalid_entries(self):
        config = ('https://192.0.2.11=secret-a, garbage, https://192.0.2.11=secret-b, '
                  '=nopass, https://=pw')
        parsed = webcol.routers(config)
        self.assertEqual(parsed, [('https://192.0.2.11', 'secret-a'),
                                  ('https://192.0.2.11', 'secret-b')])
        self.assertEqual(webcol.routers(''), [])
        self.assertEqual(webcol.routers('no-credentials-here'), [])

    def test_password_with_equals_is_preserved(self):
        # rpartition contract: everything after the last '=' is the password.
        self.assertEqual(webcol.routers('https://192.0.2.11=FixturePassword1_OnlyForTests!'),
                         [('https://192.0.2.11', 'FixturePassword1_OnlyForTests!')])
        self.assertEqual(webcol.routers('https://192.0.2.11=pa:ss=wo#rd'), [])

    def test_router_ip_extraction(self):
        self.assertEqual(webcol.router_ip('https://192.0.2.11'), '192.0.2.11')
        self.assertIsNone(webcol.router_ip('https://router.lan'))


class BackoffTests(unittest.TestCase):
    def test_exponential_growth_and_cap(self):
        self.assertEqual(webcol.failure_delay(1, False), webcol.INTERVAL)
        self.assertEqual(webcol.failure_delay(2, False), 2 * webcol.INTERVAL)
        self.assertEqual(webcol.failure_delay(3, False), 4 * webcol.INTERVAL)
        self.assertEqual(webcol.failure_delay(50, False), webcol.MAX_BACKOFF)

    def test_login_failures_have_protection_floor(self):
        self.assertGreaterEqual(webcol.failure_delay(1, True), webcol.LOGIN_BACKOFF)
        self.assertGreaterEqual(webcol.LOGIN_BACKOFF, 5 * webcol.INTERVAL)
        self.assertIn('login-ui', webcol.LOGIN_STAGES)
        self.assertIn('proof', webcol.LOGIN_STAGES)


class MergeAndTtlTests(unittest.TestCase):
    def setUp(self):
        with webcol.LOCK:
            webcol.DATA['routers'] = {}
            webcol.DATA['updated_at'] = None

    def test_merge_sets_per_client_timestamp(self):
        webcol.merge_into_data('https://192.0.2.11', result_entry(
            [{'mac': 'aa:bb:cc:dd:ee:01', 'phy_mode': '802.11ax'}]), now=1000.0)
        view = webcol.snapshot(now=1000.0)
        client = view['by_mac']['AA:BB:CC:DD:EE:01']
        self.assertEqual(client['_ts'], 1000.0)
        self.assertEqual(client['router'], 'https://192.0.2.11')
        self.assertEqual(client['router_ip'], '192.0.2.11')
        self.assertTrue(view['routers']['https://192.0.2.11']['fresh'])

    def test_ttl_expiration_drops_clients_and_router_freshness(self):
        webcol.merge_into_data('https://192.0.2.11', result_entry(
            [{'mac': 'aa:bb:cc:dd:ee:01'}]), now=1000.0)
        self.assertEqual(len(webcol.snapshot(now=1000.0 + webcol.TTL_SECONDS)['by_mac']), 1)
        expired = webcol.snapshot(now=1000.0 + webcol.TTL_SECONDS + 1)
        self.assertEqual(expired['by_mac'], {})
        self.assertFalse(expired['routers']['https://192.0.2.11']['fresh'])

    def test_newest_observation_wins_across_routers(self):
        webcol.merge_into_data('https://192.0.2.11', result_entry(
            [{'mac': 'aa:bb:cc:dd:ee:01', 'rate_mbps': 100}]), now=1000.0)
        webcol.merge_into_data('https://192.0.2.11', result_entry(
            [{'mac': 'aa:bb:cc:dd:ee:01', 'rate_mbps': 200}]), now=2000.0)
        view = webcol.snapshot(now=2000.0)
        self.assertEqual(view['by_mac']['AA:BB:CC:DD:EE:01']['rate_mbps'], 200)
        self.assertEqual(view['by_mac']['AA:BB:CC:DD:EE:01']['router'], 'https://192.0.2.11')

    def test_snapshot_is_a_private_copy(self):
        webcol.merge_into_data('https://192.0.2.11', result_entry(
            [{'mac': 'aa:bb:cc:dd:ee:01'}]), now=1000.0)
        view = webcol.snapshot(now=1000.0)
        view['by_mac']['AA:BB:CC:DD:EE:01']['phy_mode'] = 'tampered'
        view['routers']['https://192.0.2.11']['fresh'] = 'tampered'
        again = webcol.snapshot(now=1000.0)
        self.assertNotIn('phy_mode', again['by_mac']['AA:BB:CC:DD:EE:01'])
        self.assertIs(again['routers']['https://192.0.2.11']['fresh'], True)

    def test_health_is_per_router_not_cycle_timestamp(self):
        webcol.merge_into_data('https://192.0.2.11', result_entry(), now=1000.0)
        webcol.merge_into_data('https://192.0.2.12', result_entry(), now=400.0)
        view = webcol.snapshot(now=1100.0)
        self.assertTrue(view['routers']['https://192.0.2.11']['fresh'])
        self.assertFalse(view['routers']['https://192.0.2.12']['fresh'])


class CollectorPolicyTests(unittest.TestCase):
    def test_failures_back_off_and_success_resets(self):
        collector = webcol.Collector()
        self.assertTrue(collector.due('r1', now=100.0))
        collector.record_failure('r1', 'login-ui', now=100.0)
        self.assertFalse(collector.due('r1', now=100.0 + 60))
        self.assertTrue(collector.due('r1', now=100.0 + webcol.LOGIN_BACKOFF))
        self.assertEqual(collector.failures['r1'], 1)
        collector.record_failure('r1', 'login-ui', now=100.0 + webcol.LOGIN_BACKOFF)
        self.assertEqual(collector.failures['r1'], 2)
        self.assertGreaterEqual(collector.next_attempt['r1'], 100.0 + 2 * webcol.LOGIN_BACKOFF)
        collector.record_success('r1')
        self.assertEqual(collector.failures['r1'], 0)
        self.assertTrue(collector.due('r1', now=0.0))
        self.assertEqual(collector.next_attempt['r1'], 0)

    def test_state_view_reports_backoff(self):
        collector = webcol.Collector()
        collector.record_failure('r1', 'no-button', now=100.0)
        view = collector.state_view(now=101.0)
        self.assertEqual(view['r1']['failures'], 1)
        self.assertEqual(view['r1']['last_stage'], 'no-button')
        self.assertGreater(view['r1']['retry_in'], 0)


class FakePage:
    def __init__(self, results=()):
        self.results = list(results)
        self.calls = []

    async def goto(self, *args, **kwargs):
        pass

    async def wait_for_timeout(self, ms):
        pass

    async def evaluate(self, script, args=None):
        self.calls.append('evaluate')
        result = self.results.pop(0) if self.results else {'ok': True}
        if isinstance(result, float):
            await asyncio.sleep(result)
        if isinstance(result, Exception):
            raise result
        return result


class FakeContext:
    def __init__(self, page=None, fail_new_page=False, hang_new_page=False, hang_init=False):
        self._page = page
        self._fail_new_page = fail_new_page
        self._hang_new_page = hang_new_page
        self._hang_init = hang_init
        self.closed = False

    async def new_page(self):
        if self._fail_new_page:
            raise RuntimeError('no page')
        if self._hang_new_page:
            await asyncio.sleep(30)
        return self._page

    async def add_init_script(self, script):
        if self._hang_init:
            await asyncio.sleep(30)

    async def close(self):
        self.closed = True


class HangBrowser:
    def __init__(self, ctx):
        self._ctx = ctx

    def is_connected(self):
        return True

    async def new_context(self, **kwargs):
        if self._ctx is None:
            await asyncio.sleep(30)
        return self._ctx


class FakeBrowser:
    def __init__(self, ctx):
        self._ctx = ctx

    def is_connected(self):
        return True

    async def new_context(self, **kwargs):
        return self._ctx


class BudgetAndCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_hung_new_context_is_bounded_and_next_router_progresses(self):
        # First router: new_context never returns; the total budget must abort
        # it and the cycle must still serve the second router. The direct
        # transport fails with a fallback-eligible schema stage so the
        # browserless path is exercised.
        page = FakePage(results=[{'ok': True, 'logged_in': True, 'clients': [],
                                  'ssids': [], 'version': 'x'}, {'ok': True}])
        good_ctx = FakeContext(page)
        collector = webcol.Collector()
        collector.browser = FakeBrowser(FakeContext(FakePage()))  # keep ensure_browser happy.
        patch_direct_transport(self, {})
        with webcol.LOCK:
            webcol.DATA['routers'] = {}
        original = webcol.collect_router
        calls = {'n': 0}

        async def fake_collect(browser, host, password):
            calls['n'] += 1
            if calls['n'] == 1:
                return await original(HangBrowser(None), host, password)
            return await original(FakeBrowser(good_ctx), host, password)

        webcol.collect_router = fake_collect
        try:
            with unittest.mock.patch.object(webcol, 'ROUTER_GAP_SECONDS', 0), \
                 unittest.mock.patch.dict(os.environ, {'WEBROUTERS': 'https://192.0.2.11=pw-a,https://192.0.2.12=pw-b'}), \
                 unittest.mock.patch.object(webcol, 'ROUTER_BUDGET_SECONDS', 0.2):
                await collector.cycle()
        finally:
            webcol.collect_router = original
        view = webcol.snapshot()
        self.assertEqual(calls['n'], 2)                       # Progression past the hang.
        self.assertFalse(view['routers']['https://192.0.2.11']['fresh'])
        self.assertTrue(view['routers']['https://192.0.2.12']['fresh'])
        self.assertEqual(collector.failures['https://192.0.2.11'], 1)

    async def test_hung_new_context_direct_is_bounded(self):
        with unittest.mock.patch.object(webcol, 'ROUTER_BUDGET_SECONDS', 0.1):
            result = await webcol.collect_router(HangBrowser(None), 'https://192.0.2.11', 'pw')
        self.assertEqual(result['stage'], 'timeout')
        self.assertNotIn('logout', result)  # No page ever existed: nothing to log out.

    async def test_hung_new_page_is_bounded_and_context_closed(self):
        ctx = FakeContext(FakePage(), hang_new_page=True)
        with unittest.mock.patch.object(webcol, 'ROUTER_BUDGET_SECONDS', 0.1):
            result = await webcol.collect_router(FakeBrowser(ctx), 'https://192.0.2.11', 'pw')
        self.assertEqual(result['stage'], 'timeout')
        self.assertTrue(ctx.closed)

    async def test_hung_init_script_is_bounded_and_context_closed(self):
        ctx = FakeContext(FakePage(), hang_init=True)
        with unittest.mock.patch.object(webcol, 'ROUTER_BUDGET_SECONDS', 0.1):
            result = await webcol.collect_router(FakeBrowser(ctx), 'https://192.0.2.11', 'pw')
        self.assertEqual(result['stage'], 'timeout')
        self.assertTrue(ctx.closed)

    async def test_postlogin_exception_still_attempts_logout(self):
        # Exception after authentication (e.g. deviceinfo decode) leaves the
        # auth state uncertain: the bounded logout must run anyway.
        page = FakePage(results=[RuntimeError('decode failed'), {'ok': True, 'status': 200}])
        ctx = FakeContext(page)
        result = await webcol.collect_router(FakeBrowser(ctx), 'https://192.0.2.11', 'pw')
        self.assertEqual(result['stage'], 'exception:RuntimeError')
        self.assertEqual(page.calls, ['evaluate', 'evaluate'])
        self.assertEqual(result['logout'], 'ok')
        self.assertTrue(ctx.closed)

    async def test_http200_application_rejection_is_not_logout_success(self):
        page = FakePage(results=[{'ok': False, 'stage': 'wifi-schema', 'logged_in': True},
                                 {'ok': False, 'status': 200}])
        ctx = FakeContext(page)
        result = await webcol.collect_router(FakeBrowser(ctx), 'https://192.0.2.11', 'pw')
        self.assertEqual(result['logout'], 'invalid')

    async def test_router_budget_timeout_tries_logout_and_closes_context(self):
        page = FakePage(results=[30.0])  # evaluate hangs past the budget
        ctx = FakeContext(page)
        with unittest.mock.patch.object(webcol, 'ROUTER_BUDGET_SECONDS', 0.1):
            result = await webcol.collect_router(FakeBrowser(ctx), 'https://192.0.2.11', 'pw')
        self.assertEqual(result['stage'], 'timeout')
        self.assertFalse(result['ok'])
        self.assertIn('logout', result)          # Session must not stay open.
        self.assertTrue(ctx.closed)

    async def test_logout_result_is_validated(self):
        page = FakePage(results=[{'ok': False, 'stage': 'wifi-schema', 'logged_in': True},
                                 {'ok': False}])
        ctx = FakeContext(page)
        result = await webcol.collect_router(FakeBrowser(ctx), 'https://192.0.2.11', 'pw')
        self.assertEqual(result['logout'], 'invalid')
        self.assertTrue(ctx.closed)
        self.assertEqual(page.calls, ['evaluate', 'evaluate'])  # extraction + logout only.

    async def test_new_page_failure_still_closes_context(self):
        ctx = FakeContext(FakePage(), fail_new_page=True)
        result = await webcol.collect_router(FakeBrowser(ctx), 'https://192.0.2.11', 'pw')
        self.assertTrue(result['stage'].startswith('exception:'))
        self.assertTrue(ctx.closed)
        self.assertNotIn('logout', result)  # No page survived: no session to close.

    async def test_timeout_and_schema_stages_are_not_login_stages(self):
        # Generic backoff only: no fast re-login attempts after non-auth failures.
        for stage in ('timeout', 'schema-invalid', 'extract-error', 'hostinfo-schema'):
            self.assertNotIn(stage, webcol.LOGIN_STAGES)
            self.assertEqual(webcol.failure_delay(1, stage in webcol.LOGIN_STAGES),
                             webcol.INTERVAL)


class CycleSchemaTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._gap = webcol.ROUTER_GAP_SECONDS
        self._env = os.environ.get('WEBROUTERS')
        webcol.ROUTER_GAP_SECONDS = 0
        os.environ['WEBROUTERS'] = 'https://192.0.2.11=pw-a'
        with webcol.LOCK:
            webcol.DATA['routers'] = {}
            webcol.DATA['updated_at'] = None
        self.direct_results = patch_direct_transport(self, {})

    def tearDown(self):
        webcol.ROUTER_GAP_SECONDS = self._gap
        if self._env is None:
            os.environ.pop('WEBROUTERS', None)
        else:
            os.environ['WEBROUTERS'] = self._env

    async def test_invalid_schema_is_never_marked_fresh(self):
        page = FakePage(results=[{'ok': True, 'logged_in': True, 'clients': 'not-a-list',
                                  'ssids': []}, {'ok': True}])
        ctx = FakeContext(page)
        collector = webcol.Collector()
        collector.browser = FakeBrowser(ctx)
        await collector.cycle()
        view = webcol.snapshot()
        self.assertFalse(view['routers']['https://192.0.2.11']['fresh'])
        self.assertEqual(view['by_mac'], {})
        self.assertEqual(collector.failures['https://192.0.2.11'], 1)
        self.assertTrue(ctx.closed)

    async def test_zero_clients_with_valid_schema_is_legitimate(self):
        page = FakePage(results=[{'ok': True, 'logged_in': True, 'clients': [],
                                  'ssids': [{'band': '2.4GHz', 'ssid': 'Net'}], 'version': 'x'},
                                 {'ok': True}])
        ctx = FakeContext(page)
        collector = webcol.Collector()
        collector.browser = FakeBrowser(ctx)
        await collector.cycle()
        view = webcol.snapshot()
        self.assertTrue(view['routers']['https://192.0.2.11']['fresh'])
        self.assertEqual(view['routers']['https://192.0.2.11']['clients'], 0)

    async def test_malformed_client_mac_is_rejected(self):
        result = {'ok': True, 'clients': [{'mac': 'nothex'}], 'ssids': []}
        self.assertFalse(webcol.valid_collection(result))
        result = {'ok': True, 'clients': [{'mac': 'aa:bb:cc:dd:ee:01'}], 'ssids': []}
        self.assertTrue(webcol.valid_collection(result))
        for broken in (None, {'ok': True}, {'ok': True, 'clients': None, 'ssids': []},
                       {'ok': True, 'clients': [], 'ssids': 'x'}, 'x', 42):
            self.assertFalse(webcol.valid_collection(broken))


class CycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._gap = webcol.ROUTER_GAP_SECONDS
        self._env = os.environ.get('WEBROUTERS')
        webcol.ROUTER_GAP_SECONDS = 0
        os.environ['WEBROUTERS'] = 'https://192.0.2.11=pw-a,https://192.0.2.12=pw-b'
        with webcol.LOCK:
            webcol.DATA['routers'] = {}
            webcol.DATA['updated_at'] = None
        isolate_inventory_state(self)
        self.direct_results = patch_direct_transport(self, {})

    def tearDown(self):
        webcol.ROUTER_GAP_SECONDS = self._gap
        if self._env is None:
            os.environ.pop('WEBROUTERS', None)
        else:
            os.environ['WEBROUTERS'] = self._env

    async def test_cycle_merges_success_and_backs_off_failures(self):
        self.direct_results['https://192.0.2.11'] = result_entry(
            [{'mac': 'aa:bb:cc:dd:ee:01'}])
        self.direct_results['https://192.0.2.12'] = {'ok': False, 'stage': 'login-ui'}
        collector = webcol.Collector()
        await collector.cycle()
        view = webcol.snapshot()
        self.assertIn('AA:BB:CC:DD:EE:01', view['by_mac'])
        self.assertTrue(view['routers']['https://192.0.2.11']['fresh'])
        self.assertEqual(view['routers']['https://192.0.2.11']['transport'], 'direct')
        self.assertFalse(view['routers']['https://192.0.2.12']['fresh'])
        self.assertIsNone(view['routers']['https://192.0.2.12']['updated_at'])
        self.assertEqual(collector.failures['https://192.0.2.12'], 1)
        self.direct_results['https://192.0.2.11'] = {'ok': False, 'stage': 'nonce'}
        await collector.cycle()
        self.assertEqual(collector.failures['https://192.0.2.12'], 1)

    async def test_browser_outage_never_touches_routers(self):
        attempts = []

        async def failing_collect(browser, host, password):
            attempts.append(host)
            return result_entry()

        async def broken_browser(self):
            raise ConnectionError('cdp down')

        original_collect, original_ensure = webcol.collect_router, webcol.Collector.ensure_browser
        webcol.collect_router = failing_collect
        webcol.Collector.ensure_browser = broken_browser
        try:
            collector = webcol.Collector()
            await collector.cycle()
            self.assertEqual(attempts, [])
            view = webcol.snapshot()
            self.assertEqual(view['by_mac'], {})
            self.assertFalse(view['routers']['https://192.0.2.11']['fresh'])
            self.assertEqual(collector.failures, {})  # Router is not to blame.
        finally:
            webcol.collect_router = original_collect
            webcol.Collector.ensure_browser = original_ensure


class ApiDirectTransportTests(unittest.IsolatedAsyncioTestCase):
    HOST = 'https://192.0.2.11'

    def setUp(self):
        self._gap = webcol.ROUTER_GAP_SECONDS
        self._env = os.environ.get('WEBROUTERS')
        self._direct_only = webcol.DIRECT_ONLY
        webcol.ROUTER_GAP_SECONDS = 0
        os.environ['WEBROUTERS'] = '%s=pw-a' % self.HOST
        with webcol.LOCK:
            webcol.DATA['routers'] = {}
            webcol.DATA['updated_at'] = None
        self.inventory_path = isolate_inventory_state(self)
        self.direct_results = patch_direct_transport(self, {})

    def tearDown(self):
        webcol.ROUTER_GAP_SECONDS = self._gap
        webcol.DIRECT_ONLY = self._direct_only
        if self._env is None:
            os.environ.pop('WEBROUTERS', None)
        else:
            os.environ['WEBROUTERS'] = self._env

    async def test_direct_success_is_primary_and_skips_browserless(self):
        self.direct_results[self.HOST] = result_entry(
            [{'mac': 'aa:bb:cc:dd:ee:01'}], [{'band': '5g', 'ssid': 'ExampleSSID'}])
        attempts = []

        async def spy(browser, host, password):
            attempts.append(host)

        collector = webcol.Collector()
        with unittest.mock.patch.object(webcol, 'collect_router', spy), \
                unittest.mock.patch.object(webcol.Collector, 'ensure_browser',
                                           _booming_method('browserless must not be contacted')):
            await collector.cycle()
        self.assertEqual(attempts, [])
        self.assertEqual(collector.transport_view()[self.HOST]['direct'], 1)
        self.assertEqual(collector.failures.get(self.HOST, 0), 0)
        view = webcol.snapshot()
        self.assertTrue(view['routers'][self.HOST]['fresh'])
        self.assertIsNotNone(view['routers'][self.HOST]['last_success_age'])
        self.assertIsInstance(view['routers'][self.HOST]['inventory'], dict)

    async def test_inventory_registry_is_persisted(self):
        self.direct_results[self.HOST] = result_entry(
            [{'mac': 'aa:bb:cc:dd:ee:01'}],
            [{'band': '5g', 'ssid': 'ExampleSSID'}])
        result = {'ok': True, 'clients': [{'mac': 'aa:bb:cc:dd:ee:01'}],
                  'ssids': [{'band': '5g', 'ssid': 'ExampleSSID'}],
                  'inventory': {'radios': [], 'profiles': [
                      {'band': '5g', 'ssid': 'ExampleSSID', 'native_id': 2, 'usage': 'primary',
                       'enabled': True, 'channel_configured': 128, 'power': '100%', 'wmm': True}]},
                  'device': {'model': 'WUKUN-BE32'}}
        collector = webcol.Collector()
        enriched = collector.build_inventory(result)
        self.assertEqual(enriched['inventory']['counts']['primary'], 1)
        self.assertTrue(enriched['inventory_persisted'])
        self.assertTrue(os.path.exists(self.inventory_path))

    async def test_credentials_do_not_open_browserless(self):
        self.direct_results[self.HOST] = {'ok': False, 'stage': 'nonce',
                                          'reason': 'credentials', 'login_rejected': True}
        collector = webcol.Collector()
        with unittest.mock.patch.object(webcol.Collector, 'ensure_browser',
                                        _booming_method('no fallback on credentials')):
            await collector.cycle()
        self.assertEqual(collector.failures, {})
        block = collector.credential_block[self.HOST] - time.monotonic()
        self.assertGreaterEqual(block, webcol.LOGIN_BACKOFF - 1)

    async def test_server_proof_failure_does_not_open_browserless(self):
        self.direct_results[self.HOST] = {'ok': False, 'stage': 'proof',
                                          'reason': 'server-proof', 'logged_in': True}
        collector = webcol.Collector()
        with unittest.mock.patch.object(webcol.Collector, 'ensure_browser',
                                        _booming_method('no fallback on unverified proof')):
            await collector.cycle()
        self.assertIsNotNone(collector.credential_block.get(self.HOST))
        self.assertGreaterEqual(
            collector.credential_block[self.HOST] - time.monotonic(),
            webcol.LOGIN_BACKOFF - 1)

    async def test_direct_only_mode_never_connects_browserless(self):
        self.direct_results[self.HOST] = {'ok': False, 'stage': 'wifi-schema'}
        webcol.DIRECT_ONLY = True
        collector = webcol.Collector()
        with unittest.mock.patch.object(webcol.Collector, 'ensure_browser',
                                        _booming_method('direct-only')):
            await collector.cycle()
        self.assertEqual(collector.transport_view(), {})

    async def test_direct_active_host_is_skipped_without_failure(self):
        class Pending:
            def done(self):
                return False

        collector = webcol.Collector()
        collector.direct_pending[self.HOST] = Pending()
        await collector.cycle()
        self.assertEqual(collector.failures, {})

    async def test_verify_tls_is_opt_in_only(self):
        captured = {}

        class FakeClient:
            def __init__(self, host, password, **kwargs):
                captured.update(kwargs)

        with unittest.mock.patch.object(webcol.huawei_api, 'HuaweiDirectClient', FakeClient):
            webcol.Collector()._build_direct_client(self.HOST, 'pw')
            self.assertTrue(captured['verify_tls'])
            self.assertEqual(captured['total_budget'], webcol.DIRECT_TOTAL_SECONDS)
            captured.clear()
            webcol.Collector(direct_verify_tls=False)._build_direct_client(self.HOST, 'pw')
            self.assertFalse(captured['verify_tls'])

    async def test_snapshot_and_policy_expose_transport_state(self):
        self.direct_results[self.HOST] = result_entry([{'mac': 'aa:bb:cc:dd:ee:01'}])
        collector = webcol.Collector()
        await collector.cycle()
        policy = collector.state_view()
        self.assertIn(self.HOST, policy)
        self.assertIn('retry_in', policy[self.HOST])
        self.assertIn('failures', policy[self.HOST])
        self.assertEqual(collector.transport_view()[self.HOST]['browserless'], 0)


class StatsPlumbingTests(unittest.TestCase):
    def setUp(self):
        with webcol.LOCK:
            webcol.DATA['routers'] = {}
            webcol.DATA['updated_at'] = None

    def raw(self, processstatus=None):
        return {'deviceinfo': {'SoftwareVersion': 'V1', 'SerialNumber': 'SN'},
                'hostinfo': [], 'wifi': {'WifiConfig': []}, 'processstatus': processstatus}

    def test_browserless_normalization_parses_the_gauge(self):
        normalized = webcol.normalize_browserless(self.raw(
            [{'Name': 'Total', 'CpuUsage': 5, 'MemUsage': 36}]))
        self.assertEqual(normalized['stats'], {'cpu_percent': 5, 'mem_percent': 36})
        self.assertIsNone(normalized['stats_reason'])
        self.assertIsNotNone(normalized['stats_observed_at'])

    def test_browserless_without_the_gauge_marks_unsupported(self):
        normalized = webcol.normalize_browserless(self.raw(None))
        self.assertIsNone(normalized['stats'])
        self.assertEqual(normalized['stats_reason'], 'unsupported')

    def test_merge_and_snapshot_expose_fresh_stats(self):
        webcol.merge_into_data('https://192.0.2.11',
                               {**result_entry(), 'stats': {'cpu_percent': 5, 'mem_percent': 36},
                                'stats_reason': None, 'stats_observed_at': 1000.0}, now=1000.0)
        router = webcol.snapshot(now=1000.0)['routers']['https://192.0.2.11']
        self.assertEqual(router['stats']['cpu_percent'], 5)
        self.assertTrue(router['stats_fresh'])

    def test_absent_stats_never_carry_old_percent(self):
        webcol.merge_into_data('https://192.0.2.11',
                               {**result_entry(), 'stats': {'cpu_percent': 5, 'mem_percent': 36},
                                'stats_reason': None, 'stats_observed_at': 1000.0}, now=1000.0)
        webcol.merge_into_data('https://192.0.2.11',
                               {**result_entry(), 'stats': None,
                                'stats_reason': 'unsupported'}, now=1010.0)
        router = webcol.snapshot(now=1010.0)['routers']['https://192.0.2.11']
        self.assertIsNone(router['stats'])
        self.assertFalse(router['stats_fresh'])
        self.assertEqual(router['stats_reason'], 'unsupported')


class BrowserlessFetchBudgetTests(unittest.TestCase):
    """Executes the real in-page fetch helper under bun/node with a mocked peer.

    The peer resolves the headers immediately and then never resolves the body:
    the regression was that the AbortController timer was cleared once the
    headers arrived, so a stalled body hung the whole session. The helper must
    still abort inside its budget while awaiting ``response.json()``. Bun is
    preferred for new JS execution; Node remains a fallback where only it exists.
    """

    ENGINE = shutil.which('bun') or shutil.which('node')

    def test_abort_budget_covers_the_response_body_parse(self):
        if not self.ENGINE:
            self.skipTest('no bun/node JS engine available for offline execution')
        script = (
            '(async () => {\n'
            + webcol.JS_FETCH_JSON_HELPER
            + "\nglobal.fetch = (url, opts) => Promise.resolve({ok: true, status: 200,"
              " json: () => new Promise((resolve, reject) => {"
              " opts.signal.addEventListener('abort', () =>"
              " reject(new DOMException('aborted', 'AbortError'))); })});\n"
            + 'const started = Date.now();\n'
            + "let rejected = false, errorName = '';\n"
            + "try { await fetchJson('/api/system/processstatus', {}, 250); }\n"
            + "catch (e) { rejected = true; errorName = e.name; }\n"
            + 'console.log(JSON.stringify({rejected: rejected, errorName: errorName,'
              ' elapsed: Date.now() - started}));\n'
            + '})();\n'
        )
        result = subprocess.run([self.ENGINE, '-e', script], capture_output=True,
                                text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        out = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(out['rejected'], out)
        self.assertEqual(out['errorName'], 'AbortError')
        self.assertGreaterEqual(out['elapsed'], 200)
        self.assertLess(out['elapsed'], 2000)

    def test_the_shared_helper_is_the_one_embedded_in_the_login_script(self):
        self.assertIn(webcol.JS_FETCH_JSON_HELPER, webcol.LOGIN_AND_EXTRACT)

    def test_embedded_scripts_parse_as_functions(self):
        if not self.ENGINE:
            self.skipTest('no bun/node JS engine available for offline execution')
        for name in ('LOGIN_AND_EXTRACT', 'LOGOUT_SCRIPT'):
            with self.subTest(script=name):
                script = 'const handler = ' + getattr(webcol, name) + ';\nconsole.log(typeof handler);\n'
                result = subprocess.run([self.ENGINE, '-e', script], capture_output=True,
                                        text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), 'function')

    def test_hung_optional_stats_never_discards_a_valid_core(self):
        raw = {'deviceinfo': {'SoftwareVersion': 'V1', 'SerialNumber': 'SN'},
               'hostinfo': [{'Active': True, 'phyMode': '802.11ax',
                             'Frequency': '5GHz',
                             'MACAddress': 'aa:bb:cc:dd:ee:01'}],
               'wifi': {'WifiConfig': [{'FrequencyBand': '5G', 'WifiSsid': 'Main',
                                        'WifiEnable': True, 'ID': 1}]},
               'processstatus': None}
        normalized = webcol.normalize_browserless(raw)
        self.assertTrue(webcol.valid_fallback(normalized))
        self.assertIsNone(normalized['stats'])
        self.assertEqual(normalized['stats_reason'], 'unsupported')
        self.assertEqual(len(normalized['clients']), 1)


class CycleConcurrencyTests(unittest.TestCase):
    def test_slow_webonly_poll_does_not_serialise_the_normal_poll(self):
        collector = webcol.Collector()

        async def fake_collect(ensure, host, password):
            await asyncio.sleep(0.2)
            return {'ok': False, 'stage': 'timeout'}

        collector.collect_host = fake_collect
        with unittest.mock.patch.object(webcol, 'routers',
                                        return_value=[('https://192.0.2.11', 'p')]), \
                unittest.mock.patch.object(webcol.webonly, 'webonly_routers',
                                           return_value=[('https://192.168.3.1', 'p')]), \
                unittest.mock.patch.object(webcol, 'ROUTER_GAP_SECONDS', 0):
            started = time.monotonic()
            asyncio.run(collector.cycle())
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.35)  # Overlapped, not 2x0.2 serialised.


class WebonlyDirectOnlyTests(unittest.TestCase):
    def test_webonly_schema_failure_never_uses_the_browser(self):
        collector = webcol.Collector()
        calls = []

        async def fake_direct(host, password):
            return {'ok': True, 'transport': 'direct', 'stage': 'wifi-schema'}

        async def boom(*args, **kwargs):
            calls.append('browser')
            raise AssertionError('browser must not run for web-only')

        collector.collect_direct = fake_direct
        collector.ensure_browser = boom
        with unittest.mock.patch.object(webcol, 'collect_router', boom), \
                unittest.mock.patch.object(webcol, 'DIRECT_ONLY', False):
            result = asyncio.run(collector.collect_host(
                collector.ensure_browser, 'https://192.0.2.1', 'pw', direct_only=True))
        self.assertEqual(calls, [])
        self.assertTrue(result.get('browserless_unavailable'))
        self.assertEqual(result.get('browserless_skipped'), 'webonly-direct-only')

    def test_normal_cpe_still_attempts_the_browser_fallback(self):
        collector = webcol.Collector()
        calls = []

        async def fake_direct(host, password):
            return {'ok': True, 'transport': 'direct', 'stage': 'wifi-schema'}

        async def boom(*args, **kwargs):
            calls.append('browser')
            raise RuntimeError('no browser')

        collector.collect_direct = fake_direct
        collector.ensure_browser = boom
        with unittest.mock.patch.object(webcol, 'DIRECT_ONLY', False):
            result = asyncio.run(collector.collect_host(
                collector.ensure_browser, 'https://192.0.2.1', 'pw'))
        self.assertEqual(calls, ['browser'])
        self.assertTrue(result.get('browserless_unavailable'))


class BrowserOriginGuardTests(unittest.TestCase):
    def test_redirected_page_never_receives_the_password(self):
        filled = []

        class Page:
            url = 'http://evil.example.com/'

            async def goto(self, *args, **kwargs):
                pass

            async def wait_for_timeout(self, *args):
                pass

            async def evaluate(self, script, *args):
                if script == webcol.LOGIN_AND_EXTRACT:
                    filled.append('login')
                    raise AssertionError('password filled on a foreign origin')
                return {'ok': False}

        class Ctx:
            async def route(self, *args):
                pass

            async def add_init_script(self, *args):
                pass

            async def new_page(self):
                return Page()

            async def close(self):
                pass

        class Browser:
            async def new_context(self, **kwargs):
                return Ctx()

        result = asyncio.run(webcol.collect_router(Browser(), 'http://192.0.2.9', 'pw'))
        self.assertEqual(filled, [])
        self.assertFalse(result['ok'])
        self.assertTrue(str(result.get('stage', '')).startswith('exception'))


if __name__ == '__main__':
    unittest.main()
