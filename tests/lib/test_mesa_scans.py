import pytest
from contextlib import contextmanager
from unittest.mock import patch, call, mock_open
from mesa_toolkit import __version__
import mesa_toolkit.lib.mesa_scans as mesa_scans


class TestMasscan():
    DATA_ALIVE_HOSTS_OPEN_PORTS= """
Timestamp: 1693588094	192.168.2.2
Timestamp: 1693588099	192.168.2.4
Timestamp: 1693588095	192.168.2.62
Timestamp: 1693588090	192.168.2.129
Timestamp: 1693588102	192.168.2.174
Timestamp: 1693588094	10.1.1.2
Timestamp: 1693588099	10.1.1.4
Timestamp: 1693588095	10.1.1.62
Timestamp: 1693588090	10.1.1.129
Timestamp: 1693588102	10.1.1.174
"""


    @pytest.fixture
    def masscan_inputs(self):
        return("rv1234", "scope.txt", "exclude.txt")


    def mock_file_manager(read_data=None):
        # Create a mock file object
        m = mock_open(read_data=read_data)

        # Yield the mock file object within the context
        return m


    def test_masscan_scan_no_input(self, masscan_inputs):
        rv_num, input_file, exclude_file = masscan_inputs

        # assert that calling masscan with no input file raises a ValueError
        with pytest.raises(ValueError):
            mesa_scans.masscan(rv_num, input_file=None, exclude_file=None)


    @patch('builtins.open', new_callable=mock_open, read_data=DATA_ALIVE_HOSTS_OPEN_PORTS)
    @patch('mesa_toolkit.lib.mesa_scans.run_gnmap_parser')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_masscan_calls_no_exclude(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_gnmap_parser, mock_builtin_open, masscan_inputs
    ):
        rv_num, input_file, exclude_file = masscan_inputs
        masscan_folders = f'{rv_num}{mesa_scans.MASSCAN_FOLDERS}'

        mesa_scans.masscan(rv_num, input_file=input_file)

        mock_system.assert_has_calls([
            call(f'mkdir -p {masscan_folders}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'masscan -Pn -n -iL {input_file} -p 21,22,23,25,53,88,111,137,139,445,80,443,8443,8080,8000,1812,1433,135,4443,110,2222,993,2077,2078,3306,3389,4786,6970,636,389 --rate 1500 -oG {rv_num}_masscan.gnmap', write_start_file=True)
        ])
        mock_builtin_open.assert_has_calls([
            call('./Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt', 'r', encoding="utf-8"),
            call().__enter__(),
            call().readlines(),
            call().__exit__(None, None, None),
            call('./discovered-subnets.txt', 'w', encoding='utf-8'),
            call().__enter__(),
            call().write('192.168.2.0/24\n'),
            call().write('10.1.1.0/24\n'),
            call().__exit__(None, None, None)
        ], any_order=True)

        mock_chdir.assert_has_calls([
            call(f'{masscan_folders}'),
            call(f'/home/user')
        ])
        mock_gnmap_parser.assert_called_once()
        mock_getcwd.assert_called_once()


    @patch('builtins.open', new_callable=mock_open, read_data=DATA_ALIVE_HOSTS_OPEN_PORTS)
    @patch('mesa_toolkit.lib.mesa_scans.run_gnmap_parser')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_masscan_calls(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_gnmap_parser, mock_builtin_open, masscan_inputs
    ):
        rv_num, input_file, exclude_file = masscan_inputs
        masscan_folders = f'{rv_num}{mesa_scans.MASSCAN_FOLDERS}'

        mesa_scans.masscan(rv_num, input_file=input_file, exclude_file=exclude_file)

        mock_system.assert_has_calls([
            call(f'mkdir -p {masscan_folders}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'masscan -Pn -n -iL {input_file} -p 21,22,23,25,53,88,111,137,139,445,80,443,8443,8080,8000,1812,1433,135,4443,110,2222,993,2077,2078,3306,3389,4786,6970,636,389 --rate 1500 -oG {rv_num}_masscan.gnmap --excludefile {exclude_file}', write_start_file=True)
        ])
        mock_builtin_open.assert_has_calls([
            call('./Parsed-Results/Host-Lists/Alive-Hosts-Open-Ports.txt', 'r', encoding="utf-8"),
            call().__enter__(),
            call().readlines(),
            call().__exit__(None, None, None),
            call('./discovered-subnets.txt', 'w', encoding='utf-8'),
            call().__enter__(),
            call().write('192.168.2.0/24\n'),
            call().write('10.1.1.0/24\n'),
            call().__exit__(None, None, None)
        ], any_order=True)
        mock_chdir.assert_has_calls([
            call(f'{masscan_folders}'),
            call(f'/home/user')
        ])
        mock_gnmap_parser.assert_called_once()
        mock_getcwd.assert_called_once()



class TestDiscovery():
    @pytest.fixture
    def fixture_discovery_inputs(self):
        return("rv1234", "scope.txt", "exclude.txt")

    @patch('os.path.isfile', return_value=False)
    def test_discovery_no_input_no_previous_scans(self, mock_isfile, fixture_discovery_inputs):
        rv_num, input_file, exclude_file = fixture_discovery_inputs

        # assert that calling discovery with no input file raises a ValueError
        with pytest.raises(ValueError):
            mesa_scans.discovery(rv_num, input_file=None, exclude_file=None)


    @patch('mesa_toolkit.lib.mesa_scans.mark_folder_complete')
    @patch('os.path.isfile', return_value=True)
    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file')
    @patch('mesa_toolkit.lib.mesa_scans.run_gnmap_parser')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_discovery_calls_no_input(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_gnmap_parser, mock_get_discovered_hosts_file, mock_isfile,
        mock_mark_folder_complete, fixture_discovery_inputs
    ):
        rv_num = fixture_discovery_inputs[0]
        nmap_folders_discovery = f'{rv_num}{mesa_scans.NMAP_FOLDERS_DISC}'
        masscan_folders = f'{rv_num}{mesa_scans.MASSCAN_FOLDERS}'

        mesa_scans.discovery(rv_num)

        assert mock_get_discovered_hosts_file.call_count == 0
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {nmap_folders_discovery}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'nmap -Pn -n -sS -p 21,22,23,25,53,88,111,137,139,445,80,443,8443,8080,8000,1812,1433,135,4443,110,2222,993,2077,2078,3306,3389,4786,6970,636,389 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA {nmap_folders_discovery}{rv_num}_DISC -iL {masscan_folders}discovered-subnets.txt', path=nmap_folders_discovery, write_start_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{nmap_folders_discovery}'),
            call(f'/home/user')
        ])
        mock_gnmap_parser.assert_called_once()
        mock_mark_folder_complete.assert_called_once()


    @patch('mesa_toolkit.lib.mesa_scans.mark_folder_complete')
    @patch('mesa_toolkit.lib.mesa_scans.run_gnmap_parser')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_discovery_calls_no_exclude(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_gnmap_parser, mock_mark_folder_complete, fixture_discovery_inputs
    ):
        rv_num, input_file, exclude_file = fixture_discovery_inputs
        nmap_folders_disc = f'{rv_num}{mesa_scans.NMAP_FOLDERS_DISC}'

        mesa_scans.discovery(rv_num, input_file=input_file)

        mock_system.assert_has_calls([
            call(f'mkdir -p {nmap_folders_disc}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'nmap -Pn -n -sS -p 21,22,23,25,53,88,111,137,139,445,80,443,8443,8080,8000,1812,1433,135,4443,110,2222,993,2077,2078,3306,3389,4786,6970,636,389 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA {nmap_folders_disc+rv_num}_DISC -iL {input_file}', path=nmap_folders_disc, write_start_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{nmap_folders_disc}'),
            call(f'/home/user')
        ])
        mock_gnmap_parser.assert_called_once()
        mock_getcwd.assert_called_once()
        mock_mark_folder_complete.assert_called_once()


    @patch('mesa_toolkit.lib.mesa_scans.mark_folder_complete')
    @patch('mesa_toolkit.lib.mesa_scans.run_gnmap_parser')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_discovery_calls(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_gnmap_parser, mock_mark_folder_complete, fixture_discovery_inputs
    ):
        rv_num, input_file, exclude_file = fixture_discovery_inputs
        nmap_folders_disc = f'{rv_num}{mesa_scans.NMAP_FOLDERS_DISC}'

        mesa_scans.discovery(rv_num, input_file=input_file, exclude_file=exclude_file)

        mock_system.assert_has_calls([
            call(f'mkdir -p {nmap_folders_disc}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'nmap -Pn -n -sS -p 21,22,23,25,53,88,111,137,139,445,80,443,8443,8080,8000,1812,1433,135,4443,110,2222,993,2077,2078,3306,3389,4786,6970,636,389 --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA '+nmap_folders_disc+rv_num+'_DISC -iL '+input_file+' --excludefile '+exclude_file, path=nmap_folders_disc, write_start_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{nmap_folders_disc}'),
            call(f'/home/user')
        ])
        mock_gnmap_parser.assert_called_once()
        mock_getcwd.assert_called_once()
        mock_mark_folder_complete.assert_called_once()


class TestFullPort():
    @pytest.fixture
    def fixture_full_port_inputs(self):
        return("rv1234", "scope.txt", "exclude.txt")


    @patch('os.path.isfile', return_value=False)
    def test_full_port_no_input_no_previous_scans(self, fixture_full_port_inputs):
        with pytest.raises(ValueError):
            mesa_scans.full_port(fixture_full_port_inputs[0])


    @patch('mesa_toolkit.lib.mesa_scans.mark_folder_complete')
    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file', return_value='hosts.txt')
    @patch('mesa_toolkit.lib.mesa_scans.run_gnmap_parser')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_full_port_calls_no_input(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_gnmap_parser, mock_get_discovered_hosts_file,
        mock_mark_folder_complete, fixture_full_port_inputs
    ):
        rv_num = fixture_full_port_inputs[0]
        nmap_folders_full = f'{rv_num}{mesa_scans.NMAP_FOLDERS_FULL}'

        mesa_scans.full_port(rv_num)

        mock_get_discovered_hosts_file.assert_called_once_with(rv_num, None, None)
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {nmap_folders_full}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'nmap -Pn -n -sV -p- --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA '+nmap_folders_full+rv_num+'_FULL'+' '+'-iL hosts.txt', path=nmap_folders_full, write_start_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{nmap_folders_full}'),
            call(f'/home/user')
        ])
        mock_gnmap_parser.assert_called_once()
        mock_mark_folder_complete.assert_called_once()


    @patch('mesa_toolkit.lib.mesa_scans.mark_folder_complete')
    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file')
    @patch('mesa_toolkit.lib.mesa_scans.run_gnmap_parser')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_full_port_calls_no_exclude(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_gnmap_parser, mock_get_discovered_hosts_file,
        mock_mark_folder_complete, fixture_full_port_inputs
    ):
        rv_num, input_file, exclude_file = fixture_full_port_inputs
        nmap_folders_full = f'{rv_num}{mesa_scans.NMAP_FOLDERS_FULL}'

        mesa_scans.full_port(rv_num, input_file=input_file)

        assert mock_get_discovered_hosts_file.call_count == 0
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {nmap_folders_full}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'nmap -Pn -n -sV -p- --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA '+nmap_folders_full+rv_num+'_FULL'+' '+'-iL '+input_file, path=nmap_folders_full, write_start_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{nmap_folders_full}'),
            call(f'/home/user')
        ])
        mock_gnmap_parser.assert_called_once()
        mock_mark_folder_complete.assert_called_once()


    @patch('mesa_toolkit.lib.mesa_scans.mark_folder_complete')
    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file')
    @patch('mesa_toolkit.lib.mesa_scans.run_gnmap_parser')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_full_port_calls(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_gnmap_parser, mock_get_discovered_hosts_file,
        mock_mark_folder_complete, fixture_full_port_inputs
    ):
        rv_num, input_file, exclude_file = fixture_full_port_inputs
        nmap_folders_full = f'{rv_num}{mesa_scans.NMAP_FOLDERS_FULL}'

        mesa_scans.full_port(rv_num, input_file=input_file, exclude_file=exclude_file)

        assert mock_get_discovered_hosts_file.call_count == 0
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {nmap_folders_full}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'nmap -Pn -n -sV -p- --min-hostgroup 255 --min-rtt-timeout 0ms --max-rtt-timeout 100ms --max-retries 1 --max-scan-delay 0 --min-rate 2000 -vvv --open -oA '+nmap_folders_full+rv_num+'_FULL'+' '+'-iL '+input_file, path=nmap_folders_full, write_start_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{nmap_folders_full}'),
            call(f'/home/user')
        ])
        mock_gnmap_parser.assert_called_once()
        mock_mark_folder_complete.assert_called_once()


class TestAquatone():
    @pytest.fixture
    def fixture_aquatone_inputs(self):
        return("rv1234", "scope.txt", "exclude.txt")

    # TODO: Mock os.path.isfile
    @patch('os.path.isfile', return_value=False)
    def test_aquatone_no_input_no_previous_scans(self, fixture_aquatone_inputs):
        with pytest.raises(ValueError):
            mesa_scans.aquatone(fixture_aquatone_inputs[0])


    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_aquatone_calls_no_input(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, fixture_aquatone_inputs
    ):
        rv_num = fixture_aquatone_inputs[0]
        aquatone_folders = f'{rv_num}{mesa_scans.AQUATONE_FOLDERS}'
        default_input = f'{rv_num}{mesa_scans.NMAP_FOLDERS_DISC}/Parsed-Results/Third-Party/PeepingTom.txt'

        with patch('os.path.isfile', return_value=True):
            with patch('os.walk', return_value=[('/', [], ['aquatone'])]):
                mesa_scans.aquatone(rv_num)

        assert mock_get_discovered_hosts_file.call_count == 0
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {aquatone_folders}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'cat {default_input}|/aquatone', write_start_file=True, write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{aquatone_folders}'),
            call(f'/home/user')
        ])


    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_aquatone_calls_no_exclude(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, fixture_aquatone_inputs
    ):
        rv_num, input_file, exclude_file = fixture_aquatone_inputs
        aquatone_folders = f'{rv_num}{mesa_scans.AQUATONE_FOLDERS}'

        with patch('os.path.isfile', return_value=True):
            with patch('os.walk', return_value=[('/', [], ['aquatone'])]):
                mesa_scans.aquatone(rv_num, input_file)

        assert mock_get_discovered_hosts_file.call_count == 0
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {aquatone_folders}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'cat scope.txt|/aquatone', write_start_file=True, write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{aquatone_folders}'),
            call(f'/home/user')
        ])


class TestVulnScans():
    @pytest.fixture
    def fixture_vuln_scans_inputs(self):
        return("rv1234", "scope.txt", "exclude.txt")


    @patch('os.path.isfile', return_value=False)
    def test_vuln_scans_no_input_no_previous_scans(self, fixture_vuln_scans_inputs):
        with pytest.raises(ValueError):
            mesa_scans.vuln_scans(fixture_vuln_scans_inputs[0])


    @patch('mesa_toolkit.lib.mesa_scans.cleanup_empty_files')
    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file', return_value='hosts.txt')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_vuln_scans_calls_no_input(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, mock_cleanup_empty_files, fixture_vuln_scans_inputs
    ):
        rv_num = fixture_vuln_scans_inputs[0]
        vuln_scans_folders = f'{rv_num}{mesa_scans.VULN_SCAN_FOLDERS}'

        with patch('os.path.isfile', return_value=True):
            with patch('os.walk', return_value=[('/', [], ['vuln_scans'])]):
                mesa_scans.vuln_scans(rv_num)

        mock_get_discovered_hosts_file.assert_called_once_with(rv_num, None, None)
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {vuln_scans_folders}')
        ])
        mock_runcommand.assert_has_calls([
            call('nuclei -l hosts.txt -etags default-login -j -o '+rv_num+'_Vulnerability_Scan.txt', write_start_file=True),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |jq > '+rv_num+'_all_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"critical"\'|jq > '+rv_num+'_critical_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"high"\'|jq > '+rv_num+'_high_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"medium"\'|jq > '+rv_num+'_medium_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"low"\'|jq > '+rv_num+'_low_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"info"\'|jq > '+rv_num+'_informational_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"unknown"\'|jq > '+rv_num+'_unknown_findings.json'),
            call('cat '+rv_num+'_critical_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_critical_affected_hosts.txt'),
            call('cat '+rv_num+'_high_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_high_affected_hosts.txt'),
            call('cat '+rv_num+'_medium_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_medium_affected_hosts.txt'),
            call('cat '+rv_num+'_low_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_low_affected_hosts.txt'),
            call('cat '+rv_num+'_informational_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_informational_affected_hosts.txt', write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{vuln_scans_folders}'),
            call(f'/home/user')
        ])
        mock_cleanup_empty_files.assert_called_once_with(vuln_scans_folders)


    @patch('mesa_toolkit.lib.mesa_scans.cleanup_empty_files')
    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file', return_value='hosts.txt')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_vuln_scans_calls_no_exclude(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, mock_cleanup_empty_files, fixture_vuln_scans_inputs
    ):
        rv_num, input_file, exclude_file = fixture_vuln_scans_inputs
        vuln_scans_folders = f'{rv_num}{mesa_scans.VULN_SCAN_FOLDERS}'

        with patch('os.path.isfile', return_value=True):
            with patch('os.walk', return_value=[('/', [], ['vuln_scans'])]):
                mesa_scans.vuln_scans(rv_num, input_file)

        assert mock_get_discovered_hosts_file.call_count == 0
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {vuln_scans_folders}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'nuclei -l {input_file} -etags default-login -j -o '+rv_num+'_Vulnerability_Scan.txt', write_start_file=True),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |jq > '+rv_num+'_all_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"critical"\'|jq > '+rv_num+'_critical_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"high"\'|jq > '+rv_num+'_high_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"medium"\'|jq > '+rv_num+'_medium_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"low"\'|jq > '+rv_num+'_low_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"info"\'|jq > '+rv_num+'_informational_findings.json'),
            call('cat '+rv_num+'_Vulnerability_Scan.txt |grep \'"severity"\':\'"unknown"\'|jq > '+rv_num+'_unknown_findings.json'),
            call('cat '+rv_num+'_critical_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_critical_affected_hosts.txt'),
            call('cat '+rv_num+'_high_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_high_affected_hosts.txt'),
            call('cat '+rv_num+'_medium_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_medium_affected_hosts.txt'),
            call('cat '+rv_num+'_low_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_low_affected_hosts.txt'),
            call('cat '+rv_num+'_informational_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_informational_affected_hosts.txt', write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{vuln_scans_folders}'),
            call(f'/home/user')
        ])
        mock_cleanup_empty_files.assert_called_once_with(vuln_scans_folders)


    def test_vuln_scans_calls(self):
        # TODO: Function doesn't take into account exclude file
        pass

class TestEncryptionCheck():
    @pytest.fixture
    def fixture_encryption_check_inputs(self):
        return("rv1234", "scope.txt", "exclude.txt")


    @patch('os.path.isfile', return_value=False)
    def test_encryption_check_no_input_no_previous_scans(self, fixture_encryption_check_inputs):
        with pytest.raises(ValueError):
            mesa_scans.encryption_check(fixture_encryption_check_inputs[0])


    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file', return_value='hosts.txt')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_encryption_check_calls_no_input(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, fixture_encryption_check_inputs
    ):
        rv_num = fixture_encryption_check_inputs[0]
        nmap_folders = rv_num + mesa_scans.NMAP_FOLDERS_DISC
        encryption_check_folders = rv_num + mesa_scans.ENCRYPTION_CHECK_FOLDERS
        cleartext_folder = rv_num + mesa_scans.CLEARTEXT_PROTOCOLS_FOLDERS

        mesa_scans.encryption_check(rv_num)

        mock_get_discovered_hosts_file.assert_called_once_with(rv_num, None, None)
        mock_getcwd.assert_called_once()
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {cleartext_folder}'),
            call(f'mkdir -p {encryption_check_folders}')
        ])
        mock_runcommand.assert_has_calls([
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/20-TCP.txt '+cleartext_folder+' 2>/dev/null', write_start_file=True),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/21-TCP.txt '+cleartext_folder+' 2>/dev/null'),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/23-TCP.txt '+cleartext_folder+' 2>/dev/null'),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/80-TCP.txt '+cleartext_folder+' 2>/dev/null'),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/8000-TCP.txt '+cleartext_folder+' 2>/dev/null'),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/8080-TCP.txt '+cleartext_folder+' 2>/dev/null', path=cleartext_folder),
            call('sslscan --targets=Scan_Targets.txt|tee rv1234_SSL_Scan_Results.txt', write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'/home/user/{encryption_check_folders}'),
            call(f'/home/user')
        ])



    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_encryption_check_calls_no_exclude(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, fixture_encryption_check_inputs
    ):
        rv_num, input_file, exclude_file = fixture_encryption_check_inputs
        nmap_folders = rv_num + mesa_scans.NMAP_FOLDERS_DISC
        encryption_check_folders = rv_num + mesa_scans.ENCRYPTION_CHECK_FOLDERS
        cleartext_folder = rv_num + mesa_scans.CLEARTEXT_PROTOCOLS_FOLDERS

        mesa_scans.encryption_check(rv_num, input_file, exclude_file)

        assert mock_get_discovered_hosts_file.call_count == 0
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {cleartext_folder}'),
            call(f'mkdir -p {encryption_check_folders}')
        ])

        mock_runcommand.assert_has_calls([
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/20-TCP.txt '+cleartext_folder+' 2>/dev/null', write_start_file=True),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/21-TCP.txt '+cleartext_folder+' 2>/dev/null'),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/23-TCP.txt '+cleartext_folder+' 2>/dev/null'),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/80-TCP.txt '+cleartext_folder+' 2>/dev/null'),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/8000-TCP.txt '+cleartext_folder+' 2>/dev/null'),
            call('cp /home/user/'+ nmap_folders + '/Parsed-Results/Port-Files/8080-TCP.txt '+cleartext_folder+' 2>/dev/null', path=cleartext_folder),
            call('sslscan --targets=Scan_Targets.txt|tee rv1234_SSL_Scan_Results.txt', write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'/home/user/{encryption_check_folders}'),
            call(f'/home/user')
        ])


    def test_vuln_scans_calls(self):
        # TODO: Function doesn't take into account exclude file
        pass


class TestDefaultLogins():
    @pytest.fixture
    def fixture_default_logins_inputs(self):
        return("rv1234", "scope.txt", "exclude.txt")


    @patch('os.path.isfile', return_value=False)
    def test_default_logins_no_input_no_previous_scans(self, fixture_default_logins_inputs):
        with pytest.raises(ValueError):
            mesa_scans.default_logins(fixture_default_logins_inputs[0])


    @patch('os.makedirs')
    @patch('mesa_toolkit.lib.mesa_scans.cleanup_empty_files')
    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file', return_value='hosts.txt')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_default_logins_calls_no_input(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, mock_cleanup_empty_files, mock_makedirs,
        fixture_default_logins_inputs
    ):
        rv_num = fixture_default_logins_inputs[0]
        nmap_folders = rv_num + mesa_scans.NMAP_FOLDERS_DISC
        default_logins_folders = rv_num + mesa_scans.DEFAULT_LOGINS_FOLDERS

        mesa_scans.default_logins(rv_num)

        mock_get_discovered_hosts_file.assert_called_once_with(rv_num, None, None)
        mock_getcwd.assert_called_once()
        assert mock_system.call_count == 0

        mock_runcommand.assert_has_calls([
            call('nuclei -l hosts.txt -tags default-login -ni -j -o '+rv_num+'_Default_Logins.txt', write_start_file=True),
            call('cat '+rv_num+'_Default_Logins.txt |jq > '+rv_num+'_all_default_logins_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"critical"\'|jq > '+rv_num+'_default_logins_critical_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"high"\'|jq > '+rv_num+'_default_logins_high_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"medium"\'|jq > '+rv_num+'_default_logins_medium_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"low"\'|jq > '+rv_num+'_default_logins_low_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"info"\'|jq > '+rv_num+'_default_logins_informational_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"unknown"\'|jq > '+rv_num+'_default_logins_unknown_findings.json'),
            call('cat '+rv_num+'_default_logins_critical_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_critical_affected_hosts.txt'),
            call('cat '+rv_num+'_default_logins_high_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_high_affected_hosts.txt'),
            call('cat '+rv_num+'_default_logins_medium_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_medium_affected_hosts.txt'),
            call('cat '+rv_num+'_default_logins_low_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_low_affected_hosts.txt'),
            call('cat '+rv_num+'_default_logins_informational_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_informational_affected_hosts.txt', write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{default_logins_folders}'),
            call(f'/home/user')
        ])
        mock_makedirs.assert_called_once_with(default_logins_folders, exist_ok=True)
        mock_cleanup_empty_files.assert_called_once_with(default_logins_folders)


    @patch('os.makedirs')
    @patch('mesa_toolkit.lib.mesa_scans.cleanup_empty_files')
    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_default_logins_calls_no_exclude(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, mock_cleanup_empty_files, mock_makedirs,
        fixture_default_logins_inputs
    ):
        rv_num, input_file, exclude_file = fixture_default_logins_inputs
        nmap_folders = rv_num + mesa_scans.NMAP_FOLDERS_DISC
        default_logins_folders = rv_num + mesa_scans.DEFAULT_LOGINS_FOLDERS

        mesa_scans.default_logins(rv_num, input_file, exclude_file)

        assert mock_get_discovered_hosts_file.call_count == 0
        mock_getcwd.assert_called_once()
        assert mock_system.call_count == 0

        mock_runcommand.assert_has_calls([
            call(f'nuclei -l {input_file} -tags default-login -ni -j -o '+rv_num+'_Default_Logins.txt', write_start_file=True),
            call('cat '+rv_num+'_Default_Logins.txt |jq > '+rv_num+'_all_default_logins_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"critical"\'|jq > '+rv_num+'_default_logins_critical_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"high"\'|jq > '+rv_num+'_default_logins_high_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"medium"\'|jq > '+rv_num+'_default_logins_medium_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"low"\'|jq > '+rv_num+'_default_logins_low_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"info"\'|jq > '+rv_num+'_default_logins_informational_findings.json'),
            call('cat '+rv_num+'_Default_Logins.txt |grep \'"severity"\':\'"unknown"\'|jq > '+rv_num+'_default_logins_unknown_findings.json'),
            call('cat '+rv_num+'_default_logins_critical_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_critical_affected_hosts.txt'),
            call('cat '+rv_num+'_default_logins_high_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_high_affected_hosts.txt'),
            call('cat '+rv_num+'_default_logins_medium_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_medium_affected_hosts.txt'),
            call('cat '+rv_num+'_default_logins_low_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_low_affected_hosts.txt'),
            call('cat '+rv_num+'_default_logins_informational_findings.json |jq -r \'.info.severity + " - " + .info.name + " - " + .host\'|sort -u > '+rv_num+'_default_logins_informational_affected_hosts.txt', write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{default_logins_folders}'),
            call(f'/home/user')
        ])
        mock_makedirs.assert_called_once_with(default_logins_folders, exist_ok=True)
        mock_cleanup_empty_files.assert_called_once_with(default_logins_folders)


    def test_default_logins_calls(self):
        # TODO: Function doesn't take into account exclude file
        pass


class TestDomainEnum():
    @pytest.fixture
    def fixture_domain_enum_inputs(self):
        return("rv1234", "domain.local", "192.168.1.1", "username", "password", "neo4j", "neo4j_password")

    @patch('os.getcwd', return_value='/home/user')
    @patch('os.system')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('shutil.rmtree')
    @patch('os.listdir', return_value=['bloodhound.zip', 'test.txt'])
    @patch('os.path.isfile', return_value=True)
    def test_domain_enum(self, mock_isfile, mock_listdir, mock_rmtree,
                        mock_run_command, mock_chdir, mock_system, mock_getcwd,
                        fixture_domain_enum_inputs):
        rv_num, domain, dc_ip, domain_user, domain_pass, neo4j_user, neo4j_pass = fixture_domain_enum_inputs
        mesa_scans.domain_enum(rv_num, domain, dc_ip, domain_user, domain_pass, neo4j_user, neo4j_pass)

        mock_system.assert_has_calls([
            call(f'mkdir -p {rv_num}{mesa_scans.DOMAINENUM_FOLDERS}'),
            call('mkdir -p BloodHound'),
            call('mkdir -p Database_Repo'),
            call(f'mkdir -p /home/user/{rv_num}{mesa_scans.DOMAINENUM_FOLDERS}Domain_Findings/'),
        ])
        mock_run_command.assert_has_calls([
            call(f'bloodhound-python -c All -d {domain} -u {domain_user} -p {domain_pass} -ns {dc_ip} --zip', write_start_file=True),
            call('knowsmore --create-db'),
            call(f'knowsmore --bloodhound --import-data /home/user/{rv_num}{mesa_scans.DOMAINENUM_FOLDERS}BloodHound/bloodhound.zip'),
            call(f'knowsmore --bloodhound --sync-to 127.0.0.1:7687 -d neo4j -u {neo4j_user} -p {neo4j_pass}'),
            call(f'bloodhunt -u {neo4j_user} -p {neo4j_pass} -q all', write_complete_file=True),
        ])
        mock_rmtree.assert_called_once_with('Database_Repo')
        mock_listdir.assert_called_once_with(f'/home/user/{rv_num}{mesa_scans.DOMAINENUM_FOLDERS}BloodHound')
        mock_chdir.assert_has_calls([
            call(f'/home/user/{rv_num}{mesa_scans.DOMAINENUM_FOLDERS}'),
            call(f'/home/user/{rv_num}{mesa_scans.DOMAINENUM_FOLDERS}BloodHound'),
            call(f'/home/user/{rv_num}{mesa_scans.DOMAINENUM_FOLDERS}'),
            call(f'/home/user/{rv_num}{mesa_scans.DOMAINENUM_FOLDERS}Database_Repo'),
            call(f'/home/user/{rv_num}{mesa_scans.DOMAINENUM_FOLDERS}'),
            call(f'/home/user/{rv_num}{mesa_scans.DOMAINENUM_FOLDERS}Domain_Findings/'),
            call(f'/home/user')
        ])

class TestSmbSigningCheck():
    @pytest.fixture
    def fixture_smb_signing_check_inputs(self):
        return("rv1234", "scope.txt", "exclude.txt")


    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file', return_value='hosts.txt')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_smb_signing_check_calls_no_input(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, fixture_smb_signing_check_inputs
    ):
        rv_num = fixture_smb_signing_check_inputs[0]
        smb_signing_check_folders = rv_num + mesa_scans.SMB_SIGNING_FOLDERS

        mesa_scans.smb_signing_check(rv_num)

        mock_get_discovered_hosts_file.assert_called_once_with(rv_num, None, None)
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {smb_signing_check_folders}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'crackmapexec smb hosts.txt --gen-relay-list {rv_num}_SMB_Signing_Disabled.txt|tee {rv_num}_SMB_Signing_Results.txt', write_start_file=True, write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{smb_signing_check_folders}'),
            call(f'/home/user')
        ])


    @patch('mesa_toolkit.lib.mesa_scans.get_discovered_hosts_file')
    @patch('os.getcwd', return_value='/home/user')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    @patch('os.system')
    def test_smb_signing_check_calls_no_input(
        self, mock_system, mock_runcommand, mock_chdir, mock_getcwd,
        mock_get_discovered_hosts_file, fixture_smb_signing_check_inputs
    ):
        rv_num, input_file, exclude_file = fixture_smb_signing_check_inputs
        smb_signing_check_folders = rv_num + mesa_scans.SMB_SIGNING_FOLDERS

        mesa_scans.smb_signing_check(rv_num, input_file, exclude_file)

        assert mock_get_discovered_hosts_file.call_count == 0
        mock_getcwd.assert_called_once()
        mock_system.assert_has_calls([
            call(f'mkdir -p {smb_signing_check_folders}')
        ])
        mock_runcommand.assert_has_calls([
            call(f'crackmapexec smb {input_file} --gen-relay-list {rv_num}_SMB_Signing_Disabled.txt|tee {rv_num}_SMB_Signing_Results.txt', write_start_file=True, write_complete_file=True)
        ])
        mock_chdir.assert_has_calls([
            call(f'{smb_signing_check_folders}'),
            call(f'/home/user')
        ])


    @patch('os.path.isfile', return_value=False)
    def test_smb_signing_check_no_input_no_previous_scans(self, fixture_smb_signing_check_inputs):
        with pytest.raises(ValueError):
            mesa_scans.smb_signing_check(fixture_smb_signing_check_inputs[0])


class TestPassPolicyCheck():
    @pytest.fixture
    def fixture_pass_policy_check_inputs(self):
        return("rv1234", "192.168.1.1", "username", "password")


    @patch('os.getcwd', return_value='/home/user')
    @patch('os.system')
    @patch('os.chdir')
    @patch('mesa_toolkit.lib.mesa_scans.run_command')
    def test_pass_policy_check(self, mock_run_command, mock_chdir, mock_system,
        mock_getcwd, fixture_pass_policy_check_inputs
    ):
        rv_num, dc_ip, domain_user, domain_pass = fixture_pass_policy_check_inputs
        mesa_scans.pass_policy_check(rv_num, dc_ip, domain_user, domain_pass)

        pass_policy_folders = rv_num + mesa_scans.PASS_POLICY_FOLDERS

        mock_system.assert_has_calls([
            call(f'mkdir -p {pass_policy_folders}')
        ])
        mock_run_command.assert_has_calls([
            call(f'crackmapexec smb {dc_ip} -u {domain_user} -p {domain_pass} --pass-pol |tee {rv_num}_Password_Policy_Results.txt', write_start_file=True, write_complete_file=True)
        ])

        mock_getcwd.assert_called_once()
        mock_chdir.assert_has_calls([
            call(pass_policy_folders),
            call(f'/home/user')
        ])
