#include "common.hpp"
#include "analyzer.hpp"
#include <iostream>

namespace {
void help() {
    std::cout<<"FetchNetworkConfig " FNC_VERSION " - local read-only GigE Vision diagnostics\n\n"
        "Usage (elevated console):\n"
        "  FetchNetworkConfig.exe\n"
        "  FetchNetworkConfig.exe [options]\n"
        "  FetchNetworkConfig.exe collect [options]  (compatible form)\n\n"
        "Offline analysis (no elevation required):\n"
        "  FetchNetworkConfig.exe analyze <result-folder-or-zip> [--output <existing folder>]\n"
        "      [--date YYYY-MM-DD] [--utc-offset +HH:MM|-HH:MM] (date default: +09:00)\n"
        "      [--log-utc-offset +HH:MM|-HH:MM] (overrides saved SDK log offset)\n"
        "  Writes one searchable analysis.html in a new folder beside the EXE.\n\n"
        "  With --date, also writes selected-events.csv and selected-events.jsonl.\n\n"
        "Without options: collect once, read the last 30 days of existing history,\n"
        "automatically copy the existing Sapera Log Server file (up to 64 MiB),\n"
        "and save a unique result folder beside the executable.\n\n"
        "Options:\n"
        "  --output <existing local folder> Override the default folder beside the EXE\n"
        "  --days <1..3650>                 Existing history window; default 30\n"
        "  --incident-time <ISO-8601>       Incident marker; timezone is required\n"
        "  --camera-mac <aa:bb:cc:dd:ee:ff> User-provided identity for cache comparison\n"
        "  --expected-camera-ip <IPv4>     User-provided address, not a camera query\n"
        "  --log-file <existing local file> Copy an existing application log (repeatable, max 16)\n"
        "  --log-utc-offset +HH:MM|-HH:MM   Explicit source timezone for SDK log timestamps\n"
        "  --app-name <program.exe>        Include related application incidents (repeatable)\n"
        "  --dump-file <existing.dmp>      Read bounded dump metadata (repeatable, max 8)\n"
        "  --attach-dumps                  Also create separate original dump attachment ZIP\n"
        "  --include-evtx                  Also export selected System/Application Record IDs\n"
        "  --help                          This help; no collection or file writes\n"
        "  --version                       Tool version; no collection or file writes\n\n"
        "Only local settings, tables and existing logs are read. No network probes,\n"
        "SDK loading, installation, settings changes, log activation or uploads.\n"
        "Only the chosen result directory receives application-owned files.\n"
        "Windows may record execution/security traces. Existing logs are not complete\n"
        "change audits. Camera configuration and actual camera IP are not queried.\n\n"
        "Exit codes: 0 collection completed (see coverage), 1 incomplete collection,\n"
        "            2 invalid arguments/output or packaging failure, 3 not elevated.\n";
}
}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc==2 && std::wstring_view(argv[1])==L"--help") {help();return 0;}
        if(argc==2 && std::wstring_view(argv[1])==L"--version") {std::cout<<FNC_VERSION<<"\n";return 0;}
        if(argc==3 && std::wstring_view(argv[1])==L"--worker")return fnc::worker_main(fnc::utf8(argv[2]));
        std::vector<std::wstring> args;for(int i=1;i<argc;++i)args.emplace_back(argv[i]);
        if(!args.empty() && args[0]==L"analyze")return fnc::analyze_main(args);
        auto options=fnc::parse_options(args);return fnc::collect(options);
    } catch(const std::exception& e) {try{fnc::console_text(std::string("Error: ")+e.what()+"\n",true);}catch(...){}return 2;}
}
