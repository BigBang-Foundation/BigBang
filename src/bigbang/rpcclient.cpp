// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcclient.h"

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_utils.h"
#include "json/json_spirit_writer_template.h"
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
#include <readline/history.h>
#include <readline/readline.h>

#include "http/httplib.h"
#include "version.h"

using namespace std;
using namespace xengine;
using namespace json_spirit;
using namespace bigbang::rpc;
using boost::asio::ip::tcp;

extern void Shutdown();

namespace bigbang
{

static char** RPCCommand_Completion(const char* text, int start, int end);
static void ReadlineCallback(char* line);

static string LocalCommandUsage(const string& command = "")
{
    ostringstream oss;
    if (command == "")
    {
        oss << "Local Command:\n";
    }
    if (command == "" || command == "quit")
    {
        oss << "  quit\t\t\t\tQuits this console.(CTRL-D)\n";
    }
    return oss.str();
}

static CRPCClient* pClient = nullptr;
static const char* prompt = "bigbang> ";

///////////////////////////////
// CRPCClient

CRPCClient::CRPCClient(bool fConsole)
  : IIOModule("rpcclient"),
    thrDispatch("rpcclient", boost::bind(fConsole ? &CRPCClient::LaunchConsole : &CRPCClient::LaunchCommand, this)), isConsoleRunning(false)
{
    nLastNonce = 0;
}

CRPCClient::~CRPCClient()
{
}

bool CRPCClient::HandleInitialize()
{
    return true;
}

void CRPCClient::HandleDeinitialize()
{
}

bool CRPCClient::HandleInvoke()
{
    if (!ThreadDelayStart(thrDispatch))
    {
        return false;
    }
    pClient = this;
    isConsoleRunning = true;
    return IIOModule::HandleInvoke();
}

void CRPCClient::HandleHalt()
{
    IIOModule::HandleHalt();

    pClient = nullptr;
    if (thrDispatch.IsRunning())
    {
#ifdef _WIN32
        DWORD out;
        INPUT_RECORD input;
        input.EventType = KEY_EVENT;
        input.Event.KeyEvent.wRepeatCount = 1;
        input.Event.KeyEvent.uChar.AsciiChar = '\0';
        WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), &input, 1, &out);
#endif
        CancelCommand();
        thrDispatch.Interrupt();
    }
    thrDispatch.Interrupt();
    isConsoleRunning = false;
    ThreadExit(thrDispatch);
}

const CRPCClientConfig* CRPCClient::Config()
{
    return dynamic_cast<const CRPCClientConfig*>(IBase::Config());
}

bool CRPCClient::GetResponse(uint64 nNonce, const std::string& content)
{
    if (Config()->fDebug)
    {
        cout << "request: " << content << endl;
    }

    httplib::Client cli(Config()->strRPCConnect, Config()->nRPCPort);
    std::string path = std::string("/") + to_string(VERSION);
    httplib::Headers headers = {
        { "Connection", "Keep-Alive" },
        { "Accept", "application/json" },
        { "User-Agent", "bigbang-json-rpc/" }
    };
    StdDebug("CRPCClient", "GetResponse post path: %s", path.c_str());
    if (!Config()->strRPCPass.empty() || !Config()->strRPCUser.empty())
    {
        cli.set_basic_auth(Config()->strRPCUser.c_str(), Config()->strRPCPass.c_str());
    }
    if (auto res = cli.Post(path.c_str(), headers, content + "\n", "application/json"))
    {
        try
        {
            if (res->status == 401)
            {
                throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
            }
            else if (res->status > 400 && res->status != 404 && res->status != 500)
            {
                ostringstream oss;
                oss << "server returned HTTP error " << res->status;
                throw runtime_error(oss.str());
            }
            else if (res->body.empty())
            {
                throw runtime_error("no response from server");
            }
        }
        catch (const std::exception& e)
        {
            cerr << e.what() << endl;
            return false;
        }

        auto spResp = DeserializeCRPCResp("", res->body);
        if (spResp->IsError())
        {
            // Error
            cerr << spResp->spError->Serialize(true) << endl;
            cerr << strServerHelpTips << endl;
        }
        else if (spResp->IsSuccessful())
        {
            cout << spResp->spResult->Serialize(true) << endl;
        }
        else
        {
            cerr << "server error: neither error nor result. resp: " << spResp->Serialize(true) << endl;
        }
        return true;
    }
    else
    {
        auto err = res.error();
        StdWarn("CRPCClient", "httpclient returned error %d", (int)err);
        cerr << "Http Client error: " << (int)err;
        return false;
    }
}

bool CRPCClient::CallRPC(CRPCParamPtr spParam, int nReqId)
{
    try
    {
        CRPCReqPtr spReq = MakeCRPCReqPtr(nReqId, spParam->Method(), spParam);
        return GetResponse(1, spReq->Serialize());
    }
    catch (exception& e)
    {
        cerr << e.what() << endl;
    }
    catch (...)
    {
        cerr << "Unknown error" << endl;
    }
    return false;
}

bool CRPCClient::CallConsoleCommand(const vector<std::string>& vCommand)
{
    if (vCommand[0] == "help")
    {
        if (vCommand.size() == 1)
        {
            cout << LocalCommandUsage() << endl;
            return false;
        }
        else
        {
            string usage = LocalCommandUsage(vCommand[1]);
            if (usage.empty())
            {
                return false;
            }
            cout << usage << endl;
        }
    }
    else
    {
        return false;
    }
    return true;
}

void CRPCClient::LaunchConsole()
{
    EnterLoop();

    fd_set fs;
    timeval timeout;
    while (isConsoleRunning)
    {
#ifdef _WIN32
        rl_callback_read_char();
#else
        FD_ZERO(&fs);
        FD_SET(STDIN_FILENO, &fs);

        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        int ret = select(1, &fs, nullptr, nullptr, &timeout);
        if (ret == -1)
        {
            cerr << "select error" << endl;
        }
        else if (ret == 0)
        {
            try
            {
                boost::this_thread::interruption_point();
            }
            catch (const boost::thread_interrupted&)
            {
                break;
            }
        }
        else
        {
            rl_callback_read_char();
        }
#endif
    }

    LeaveLoop();
}

void CRPCClient::LaunchCommand()
{
    const CRPCParam* param = dynamic_cast<const CRPCParam*>(IBase::Config());
    if (param != nullptr)
    {
        // avoid delete global pointer
        CRPCParamPtr spParam(const_cast<CRPCParam*>(param), [](CRPCParam* p) {});
        CallRPC(spParam, nLastNonce);
    }
    else
    {
        cerr << "Unknown command" << endl;
    }
    Shutdown();
}

void CRPCClient::CancelCommand()
{
}

void CRPCClient::EnterLoop()
{
    rl_catch_signals = 0;
    rl_attempted_completion_function = RPCCommand_Completion;
    rl_callback_handler_install(prompt, ReadlineCallback);
}

void CRPCClient::LeaveLoop()
{
    cout << "\n";
    rl_callback_handler_remove();
}

void CRPCClient::ConsoleHandleLine(const string& strLine)
{
    if (strLine == "quit")
    {
        cout << "quiting...\n";
        Shutdown();
        return;
    }

    vector<string> vCommand;

    // parse command line input
    // part 1: Parse pair of blank and quote(' or ")
    // part 2: If part 1 is blank, part 2 is any charactor besides blank.
    //         if part 1 is quote, part 2 is any charactor besides the quote in part 1.
    // part 3: consume the tail of match.
    boost::regex e("[ \t]*((?<quote>['\"])|[ \t]*)"
                   "((?(<quote>).*?|[^ \t]+))"
                   "(?(<quote>)\\k<quote>|([ \t]+|$))",
                   boost::regex::perl);
    boost::sregex_iterator it(strLine.begin(), strLine.end(), e);
    boost::sregex_iterator end;
    for (; it != end; it++)
    {
        string str = (*it)[3];
        vCommand.push_back(str);
    }

    if (Config()->fDebug)
    {
        cout << "command : ";
        for (auto& x : vCommand)
        {
            cout << x << ',';
        }
        cout << endl;
    }

    if (!vCommand.empty())
    {
        add_history(strLine.c_str());

        if (!CallConsoleCommand(vCommand))
        {
            try
            {
                CConfig config;

                vector<char*> argv(vCommand.size() + 1);
                argv[0] = const_cast<char*>("bigbang-cli");
                for (int i = 0; i < vCommand.size(); ++i)
                {
                    argv[i + 1] = const_cast<char*>(vCommand[i].c_str());
                }

                if (!config.Load(vCommand.size() + 1, &argv[0], "", "") || !config.PostLoad())
                {
                    return;
                }

                // help
                if (config.GetConfig()->fHelp)
                {
                    cout << config.Help() << endl;
                    return;
                }

                // call rpc
                CRPCParam* param = dynamic_cast<CRPCParam*>(config.GetConfig());
                if (param != nullptr)
                {
                    // avoid delete global point
                    CRPCParamPtr spParam(param, [](CRPCParam* p) {});
                    CallRPC(spParam, ++nLastNonce);
                }
                else
                {
                    cerr << "Unknown command" << endl;
                }
            }
            catch (CRPCException& e)
            {
                cerr << e.strMessage << strClientHelpTips << endl;
            }
            catch (exception& e)
            {
                cerr << e.what() << endl;
            }
        }
    }
}

///////////////////////////////
// readline

static char* RPCCommand_Generator(const char* text, int state)
{
    static int listIndex, len;
    if (!state)
    {
        listIndex = 0;
        len = strlen(text);
    }

    auto& list = RPCCmdList();
    for (; listIndex < list.size();)
    {
        const char* cmd = list[listIndex].c_str();
        listIndex++;
        if (strncmp(cmd, text, len) == 0)
        {
            char* r = (char*)malloc(strlen(cmd) + 1);
            strcpy(r, cmd);
            return r;
        }
    }
    return nullptr;
}

static char** RPCCommand_Completion(const char* text, int start, int end)
{
    (void)end;
    char** matches = nullptr;
    if (start == 0)
    {
        matches = rl_completion_matches(text, RPCCommand_Generator);
    }
    return matches;
}

static void ReadlineCallback(char* line)
{
    string strLine = line ? line : "quit";
    if (pClient)
    {
        pClient->ConsoleHandleLine(strLine);
    }
}

} // namespace bigbang
