import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, OrderedDict, Sequence, Union

from click.testing import CliRunner
from .forge import AwsError, FakeTime, ForgeFormatter, ForgeResult, ForgeState, K8sForgeRunner, assert_aws_token_expiration, format_pre_comment, get_dashboard_link, get_humio_logs_link, get_validator_logs_link, main, ForgeContext, LocalForgeRunner, FakeShell, FakeFilesystem, RunResult, FakeProcesses


class SpyShell(FakeShell):
    def __init__(self, command_map: Dict[str, Union[RunResult, Exception]]) -> None:
        self.command_map = command_map
        self.commands = []

    def run(self, command: Sequence[str], stream_output: bool = False) -> RunResult:
        result = self.command_map.get(" ".join(command), super().run(command))
        self.commands.append(" ".join(command))
        if isinstance(result, Exception):
            raise result
        return result

    def assert_commands(self, testcase) -> None:
        testcase.assertEqual(list(self.command_map.keys()), self.commands)


class SpyFilesystem(FakeFilesystem):
    def __init__(self, expected_writes: Dict[str, bytes], expected_reads: Dict[str, bytes]) -> None:
        self.expected_writes = expected_writes
        self.expected_reads = expected_reads
        self.writes = {}
        self.reads = []
        self.temp_count = 1

    def write(self, filename: str, contents: bytes) -> None:
        self.writes[filename] = contents

    def read(self, filename: str) -> bytes:
        self.reads.append(filename)
        return self.expected_reads.get(filename, b"")

    def assert_writes(self, testcase) -> None:
        for filename, contents in self.expected_writes.items():
            testcase.assertIn(filename, self.writes, f"{filename} was not written: {self.writes}")
            testcase.assertMultiLineEqual(self.writes[filename].decode(), contents.decode(), f"{filename} did not match expected contents")

    def assert_reads(self, testcase) -> None:
        for filename in self.expected_reads.keys():
            testcase.assertIn(filename, self.reads, f"{filename} was not read")

    def mkstemp(self) -> str:
        filename = f"temp{self.temp_count}"
        self.temp_count += 1
        return filename


def fake_context(shell=None, filesystem=None, processes=None, time=None) -> ForgeContext:
    return ForgeContext(
        shell=shell if shell else FakeShell(),
        filesystem=filesystem if filesystem else FakeFilesystem(),
        processes=processes if processes else FakeProcesses(),
        time=time if time else FakeTime(),

        forge_test_suite="banana",
        local_p99_latency_ms_threshold="6000",
        forge_runner_tps_threshold="593943",
        forge_runner_duration_secs="123",

        reuse_args=[],
        keep_args=[],
        haproxy_args=[],

        aws_account_num="123",
        aws_region="banana-east-1",

        forge_image_tag="asdf",
        forge_namespace="potato",
        forge_cluster_name="tomato",

        github_actions="false",
    )


class ForgeRunnerTests(unittest.TestCase):
    def testLocalRunner(self) -> None:
        shell = SpyShell({
            'cargo run -p forge-cli -- --suite banana --mempool-backlog 5000 '
            '--avg-tps 593943 --max-latency-ms 6000 --duration-secs 123 test '
            'k8s-swarm --image-tag asdf --namespace potato --port-forward':
            RunResult(0, b"orange"),
        })
        filesystem = SpyFilesystem({}, {})
        context = fake_context(shell, filesystem)
        runner = LocalForgeRunner()
        result = runner.run(context)
        self.assertEqual(result.state, ForgeState.PASS, result.output)
        shell.assert_commands(self)
        filesystem.assert_writes(self)
        filesystem.assert_reads(self)

    def testK8sRunner(self) -> None:
        self.maxDiff = None
        shell = SpyShell(OrderedDict([
            ("kubectl delete pod -n default -l forge-namespace=potato --force", RunResult(0, b"")),
            ("kubectl wait -n default --for=delete pod -l forge-namespace=potato", RunResult(0, b"")),
            ("kubectl apply -n default -f temp1", RunResult(0, b"")),
            ("kubectl wait -n default --timeout=5m --for=condition=Ready pod/potato-1659078000-asdf", RunResult(0, b"")),
            ("kubectl logs -n default -f potato-1659078000-asdf", RunResult(0, b"")),
            ("kubectl get pod -n default potato-1659078000-asdf -o jsonpath='{.status.phase}'", RunResult(0, b"Succeeded")),
        ]))
        cwd = Path(__file__).absolute().parent
        forge_yaml = cwd / "forge-test-runner-template.yaml"
        template_fixture = cwd / "forge-test-runner-template.fixture"
        filesystem = SpyFilesystem({
            "temp1": template_fixture.read_bytes(),
        }, {
            "testsuite/forge-test-runner-template.yaml": forge_yaml.read_bytes(),
        })
        context = fake_context(shell, filesystem)
        runner = K8sForgeRunner()
        result = runner.run(context)
        shell.assert_commands(self)
        filesystem.assert_writes(self)
        filesystem.assert_reads(self)
        self.assertEqual(result.state, ForgeState.PASS, result.output)


class TestAWSTokenExpiration(unittest.TestCase):
    def testNoAwsToken(self) -> None:
        with self.assertRaisesRegex(AwsError, "AWS token is required"): 
            assert_aws_token_expiration(None)

    def testAwsTokenExpired(self) -> None:
        expiration = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
        with self.assertRaisesRegex(AwsError, "AWS token has expired"):
            assert_aws_token_expiration(expiration)
    
    def testAwsTokenMalformed(self) -> None:
        with self.assertRaisesRegex(AwsError, "Invalid date format:.*"):
            assert_aws_token_expiration("asdlkfjasdlkjf")


class ForgeFormattingTests(unittest.TestCase):
    maxDiff = None

    def testReport(self):
        filesystem = SpyFilesystem({"test": b"banana"}, {})
        context = fake_context(filesystem=filesystem)
        result = ForgeResult.from_args(ForgeState.PASS, "test")
        context.report(result, [
            ForgeFormatter("test", lambda c, r: "banana")
        ])
        filesystem.assert_reads(self)
        filesystem.assert_writes(self)

    def testHumioLogLink(self):
        self.assertEqual(
            get_humio_logs_link("forge-pr-2983"),
            "https://cloud.us.humio.com/k8s/search?query=%24forgeLogs%28validat"
            "or_instance%3Dvalidator-0%29%20%7C%20forge-pr-2983%20&live=true&st"
            "art=24h&widgetType=list-view&columns=%5B%7B%22type%22%3A%22field%2"
            "2%2C%22fieldName%22%3A%22%40timestamp%22%2C%22format%22%3A%22times"
            "tamp%22%2C%22width%22%3A180%7D%2C%7B%22type%22%3A%22field%22%2C%22"
            "fieldName%22%3A%22level%22%2C%22format%22%3A%22text%22%2C%22width%"
            "22%3A54%7D%2C%7B%22type%22%3A%22link%22%2C%22openInNewBrowserTab%2"
            "2%3Atrue%2C%22style%22%3A%22button%22%2C%22hrefTemplate%22%3A%22ht"
            "tps%3A%2F%2Fgithub.com%2Faptos-labs%2Faptos-core%2Fpull%2F%7B%7Bfi"
            "elds%5B%5C%22github_pr%5C%22%5D%7D%7D%22%2C%22textTemplate%22%3A%2"
            "2%7B%7Bfields%5B%5C%22github_pr%5C%22%5D%7D%7D%22%2C%22header%22%3"
            "A%22Forge%20PR%22%2C%22width%22%3A79%7D%2C%7B%22type%22%3A%22field"
            "%22%2C%22fieldName%22%3A%22k8s.namespace%22%2C%22format%22%3A%22te"
            "xt%22%2C%22width%22%3A104%7D%2C%7B%22type%22%3A%22field%22%2C%22fi"
            "eldName%22%3A%22k8s.pod_name%22%2C%22format%22%3A%22text%22%2C%22w"
            "idth%22%3A126%7D%2C%7B%22type%22%3A%22field%22%2C%22fieldName%22%3"
            "A%22k8s.container_name%22%2C%22format%22%3A%22text%22%2C%22width%2"
            "2%3A85%7D%2C%7B%22type%22%3A%22field%22%2C%22fieldName%22%3A%22mes"
            "sage%22%2C%22format%22%3A%22text%22%7D%5D&newestAtBottom=true&show"
            "OnlyFirstLine=false"
        )

    def testValidatorLogsLink(self):
        self.assertEqual(
            get_validator_logs_link("aptos-perry", "perrynet", True),
            "https://es.intern.aptosdev.com/_dashboards/app/discover#/?_g=(filt"
            "ers:!(),refreshInterval:(pause:!f,value:10000),time:(from:now-15m,"
            "to:now))&_a=(columns:!(_source),filters:!(('$state':(store:appStat"
            "e),meta:(alias:!n,disabled:!f,index:'90037930-aafc-11ec-acce-2d961"
            "187411f',key:chain_name,negate:!f,params:(query:perrynet),type:phr"
            "ase),query:(match_phrase:(chain_name:perrynet))),('$state':(store:"
            "appState),meta:(alias:!n,disabled:!f,index:'90037930-aafc-11ec-acc"
            "e-2d961187411f',key:namespace,negate:!f,params:(query:aptos-perry)"
            ",type:phrase),query:(match_phrase:(namespace:aptos-perry))),('$sta"
            "te':(store:appState),meta:(alias:!n,disabled:!f,index:'90037930-aa"
            "fc-11ec-acce-2d961187411f',key:hostname,negate:!f,params:(query:ap"
            "tos-node-0-validator-0),type:phrase),query:(match_phrase:(hostname"
            ":aptos-node-0-validator-0)))),index:'90037930-aafc-11ec-acce-2d961"
            "187411f',interval:auto,query:(language:kuery,query:''),sort:!())"
        )

    def testDashboardLink(self):
        self.assertEqual(
            get_dashboard_link(
                "aptos-forge-1",
                "forge-pr-2983",
                "forge-1",
                True,
            ),
            "https://o11y.aptosdev.com/grafana/d/overview/overview?orgId=1&refr"
            "esh=10s&var-Datasource=Remote%20Prometheus%20Devinfra&var-namespac"
            "e=forge-pr-2983&var-chain_name=forge-1&refresh=10s&from=now-15m&to"
            "=now"
        )


    def testFormatPreComment(self):
        return
        context = fake_context()
        pre_comment = format_pre_comment(context)
        self.assertMultiLineEqual(pre_comment, "")



class ForgeMainTests(unittest.TestCase):
    def testMain(self):
        # TODO write some real test cases, this just covers execution
        runner = CliRunner()
        result = runner.invoke(main, ["test", "--dry-run", "--forge-cluster-name", "forge-1"])
        self.assertMultiLineEqual(result.output, "Using forge cluster: forge-1\nWrote b'fake' to temp\nForge failed\n")