"""Static regression gate for first-party collection code; not a runtime proof."""
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
forbidden = re.compile(
    r"\b(?:Reg(?:Set|Create|Delete|Restore|Load|Save|Replace)\w*|"
    r"(?:Create|Delete|Set)UnicastIpAddressEntry|(?:Create|Delete|Set)IpForwardEntry\w*|"
    r"(?:Create|Delete|Set)IpNetEntry\w*|SetIfEntry\w*|SetIpInterfaceEntry|"
    r"(?:Install|Start|Control|ChangeServiceConfig|Delete)Service\w*|"
    r"CreateService\w*|Evt(?:ClearLog|SetChannelConfigProperty|SaveChannelConfig)|"
    r"StartTrace\w*|EnableTrace\w*|Win32_Product|MsiEnumProducts\w*|"
    r"socket|WSASocket\w*|connect|WSAConnect|send|sendto|WSASend\w*|"
    r"getaddrinfo|GetAddrInfo\w*|gethostbyname|DnsQuery\w*|IcmpSendEcho\w*|"
    r"ShellExecute\w*|system|_wsystem|popen|_popen)\s*\(|"
    r"(?:->|\.)\s*(?:ExecMethod\w*|PutInstance\w*|PutClass\w*|DeleteInstance\w*|put_\w+)\s*\(",
    re.IGNORECASE,
)
failures = []
for path in (root / "src").glob("*.*"):
    if path.suffix not in {".cpp", ".hpp"}:
        continue
    text = path.read_text(encoding="utf-8")
    stripped = re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)
    if "Win32_Product" in stripped:
        failures.append(f"{path.name}: MSI repair-prone WMI class is prohibited")
    for match in forbidden.finditer(stripped):
        failures.append(f"{path.name}: prohibited API pattern {match.group()}")
    if "WBEM_FLAG_CONNECT_USE_MAX_WAIT" in text:
        if "ExecQuery" not in text or "ROOT\\\\" not in text:
            failures.append(f"{path.name}: review the fixed local WMI query allowlist")
main = (root / "src/main.cpp").read_text(encoding="utf-8")
worker = (root / "src/worker.cpp").read_text(encoding="utf-8")
common = (root / "src/common.cpp").read_text(encoding="utf-8")
for marker, text in [("if(!elevated())", worker), ("CREATE_NEW", common),
                     ("FILE_ATTRIBUTE_REPARSE_POINT", common),
                     ("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", worker),
                     ("PROC_THREAD_ATTRIBUTE_HANDLE_LIST", worker),
                     ("worker_main", main)]:
    if marker not in text:
        failures.append(f"required safety boundary missing: {marker}")
if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print("Static read-only API gate passed (runtime validation is still required).")
