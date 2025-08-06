#!/usr/bin/env python
import shlex
from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.completion import Completion, Completer
from prompt_toolkit.history import FileHistory
from scripts.cli_command_list import context
import scripts.cli_command_exec


class NestedCompleter(Completer):
    def __init__(self, words_dic=None, meta_dict=None, ignore_case=True, match_middle=False):
        if meta_dict is None:
            meta_dict = {}
        if words_dic is None:
            words_dic = {}
        self.ignore_case = ignore_case
        self.match_middle = match_middle
        self.words_dic = words_dic
        self.meta_dict = meta_dict
        self.cmd_list = []
        self.last_cmd = []
        pass

    def get_completions(self, document, complete_event):
        text_before_cursor = document.text_before_cursor
        if self.ignore_case:
            text_before_cursor = text_before_cursor.lower()

        text_before_cursor = str(text_before_cursor)
        # Moved to shlex.split to keep quoted strings together
        # text_arr = text_before_cursor.split(' ')
        text_arr = shlex.split(text_before_cursor)
        last_words = text_arr[-1]
        words = self.__get_current_words(text_arr[:-1])

        def word_matches(word):
            """ True when the word before the cursor matches. """
            if self.ignore_case:
                word = word.lower()

            # # Always return True if this is an open text match (%W) and something has been provided
            # if word == "%w" and last_words != "":
            #     return True
            # # print(word, last_words)
            if self.match_middle:
                return last_words in word
            else:
                return word.startswith(last_words)

        if words:
            self.last_cmd = []
            for tmpa in words:
                # print("get_completions:2", tmpa)
                a = tmpa["command"]
                if word_matches(a):
                    display_meta = self.meta_dict.get(a, '')
                    self.last_cmd.append(a)
                    yield Completion(a, -len(last_words), display_meta=display_meta)

    def __get_current_words(self, text_arr):
        current_dic = self.words_dic
        for tmp in text_arr:
            if tmp == ' ' or tmp == '':
                continue
            try:
                for c in current_dic:
                    if len(tmp) > 0 and c["command"] == "%W":
                        self.cmd_list.append(c["command"])
                        if "subcommands" in c:
                            current_dic = c["subcommands"]
                    if tmp in c["command"]:
                        if c["command"] not in self.cmd_list:
                            self.cmd_list.append(c["command"])
                        if "subcommands" in c:
                            current_dic = c["subcommands"]
                        else:
                            return []
                    # print(tmp, c["command"], self.cmd_list)
            except Exception:
                return []

        if current_dic:
            return list(current_dic)


def join_contexts(curcontext):
    """
    This function will join the global context with the current context.
    It will overwrite any commands in the global context with any commands
    that are defined in the current context. I.e., so if you have a
    command that generally functions one way, you can define it in the
    global context to always behave that way. Then, you can over-ride it
    in one or more specific contexts which will over-ride that default
    global behavior. It will also merge the first layer of sub-commands,
    so if you have "show" in global and "show" in a given context, it
    will merge whatever subcommands are part of both contexts.
    :param curcontext: the current context that is selected
    :return: combined list of current commands
    """
    ctx_dict = {}
    sub_dict = {}
    ctx_join = context["global"][:]
    for c in range(0, len(ctx_join)):
        # if ctx_join[c].get("special"):
        #     print(ctx_join[c].get("special"))
        sub_list = ctx_join[c].get("subcommands", {})
        for s in range(0, len(sub_list)):
            sub_dict[sub_list[s]["command"]] = {"num": c}
        ctx_dict[ctx_join[c]["command"]] = {"num": c, "sub": sub_dict}

    for c in context[curcontext]:
        # if c.get("special"):
        #     print(c.get("special"))
        if c["command"] in ctx_dict:
            if "subcommands" in c:
                for sc in c["subcommands"]:
                    # if sc.get("special"):
                    #     print(sc.get("special"))
                    if sc["command"] in ctx_dict[c["command"]]["sub"]:
                        pass
                    else:
                        ctx_join[ctx_dict[c["command"]]["num"]]["subcommands"] += [sc]
            else:
                ctx_join[ctx_dict[c["command"]]["num"]] = c
        else:
            ctx_join.append(c)

    # check for special merge_context requests
    for c in ctx_join:
        if c.get("special") and "merge_context" in c.get("special"):
            special_fxn = c.get("special").split("=")[1].split(":")
            import_cxt = context[special_fxn[0]]
            merge_cmds = special_fxn[1].split(";")
            for cxt_cmds in import_cxt:
                if cxt_cmds["command"] in merge_cmds:
                    if "subcommands" not in c:
                        c["subcommands"] = []
                    if cxt_cmds not in c["subcommands"]:
                        c["subcommands"].append(cxt_cmds)

    # check for special request to merge commands into the "no" operator
    do_merge_no = False
    no_commands = []
    merge_no_commands = None
    for c in ctx_join:
        if c.get("special") == "supports_no":
            no_commands.append(c)
        if c.get("special") and "merge_no_commands" in c.get("special"):
            do_merge_no = True
            merge_no_commands = c

    if do_merge_no and merge_no_commands:
        merge_no_commands["subcommands"] = no_commands

    # print(ctx_join)
    return ctx_join


def parse_input(strinput, curcontext, gethelp=False):
    """
    This function is designed to parse the currently typed input to
    determine what has been typed. It is called when the user
    presses ? or when they press Enter.
    :param strinput: Currently typed text at prompt
    :param contextchain: Full context chain the user is in
    :param gethelp: True if the user enters ?, otherwise False
    :return: String that will be printed to screen
    """
    modifiers = ["begin", "include", "exclude", "section"]
    basic_cmd_list = strinput.split(" ")
    try:
        cmd_list = shlex.split(strinput)
    except Exception:
        return "% Invalid input detected"

    temp_cmd = join_contexts(curcontext)
    add_modifiers = False
    mod_text = []
    sel_modifier = ""
    command_chain = []
    cur_commands = []
    out_help = []
    out_command = {}
    last_func = None
    leftovers = None
    # print(basic_cmd_list, len(basic_cmd_list), basic_cmd_list[len(basic_cmd_list) - 1])
    # shlex.split cuts of trailing whitespace, so leverage the regular split to detect those
    # print(len(cmd_list), len(basic_cmd_list))
    # if cmd_list[len(cmd_list) - 1] == "" or # disabled
    if basic_cmd_list[len(basic_cmd_list) - 1] == "":
        showhelp = True
    else:
        showhelp = False

    # print(showhelp, cmd_list, len(cmd_list) - 1, cmd_list[len(cmd_list) - 1])

    for c in cmd_list:
        cur_commands = []
        for a in temp_cmd:
            # print(a["command"], c, a["command"].find(c))
            if c != "" and (a["command"].find(c) == 0 or a["command"] == "%W"):
                command_chain.append(a["command"])
                cur_commands.append(a["command"])
                out_command = a
                temp_cmd = a.get("subcommands", {})
                if a.get("function", None) is not None:
                    last_func = a.get("function", None)
                    leftovers = "".join(strinput.split(c)[-1:]).strip()
        if out_command == {} and not strinput == "":
            return "% Invalid input detected"   # at '^' marker."

        if sel_modifier != "":
            mod_text.append(c)

        if add_modifiers:
            for m in modifiers:
                if m.find(c) == 0 and c != "":
                    sel_modifier = m
                    add_modifiers = False

        if c == "|":
            add_modifiers = True

    # generate the unabbreviated version of the command that the user typed
    curcmd = ""
    for cc in range(0, len(command_chain)):
        # if the position is a variable, show the user input instead of the variable
        # print(cc, command_chain[cc], cmd_list[cc])
        if command_chain[cc] == "%W":
            curcmd += "'" + cmd_list[cc] + "' "
        else:
            curcmd += command_chain[cc] + " "

    if gethelp:
        msg = ""
        # print(gethelp, showhelp, temp_cmd)
        if showhelp:
            if temp_cmd == {} or temp_cmd[0].get("optional"):
                # for optional subcommands, list the subcommands first
                if isinstance(temp_cmd, list) and temp_cmd[0].get("optional"):
                    for x in temp_cmd:
                        outcmd = x["command"].replace("%W", "WORD")
                        out_help.append(["", outcmd, "", x.get("help", "no help available")])

                if sel_modifier != "":
                    out_help.append(["", "LINE", "", "Regular Expression"])
                elif add_modifiers:
                    out_help.append(["", "begin", "", "Begin with the line that matches"])
                    out_help.append(["", "exclude", "", "Exclude lines that match"])
                    out_help.append(["", "include", "", "Include lines that match"])
                    out_help.append(["", "section", "", "Filter a section of output"])
                else:
                    out_help.append(["", "|", "", "Output modifiers"])
                    out_help.append(["", "<cr>", "", ""])
            else:
                for x in temp_cmd:
                    outcmd = x["command"].replace("%W", "WORD")
                    # hide commands that are flagged as special=hidden
                    if x.get("special") == "hidden":
                        continue
                    out_help.append(["", outcmd, "", x.get("help", "no help available")])
                    # if "lookup" in x:
                    #     exec_ret = scripts.cli_command_exec.lookup_func(x["lookup"])
                    #     # TODO: dynamic lookup here

            msg += "?\n" + scripts.cli_command_exec.format_data(out_help)
        else:
            if add_modifiers:
                out_help.append("|")
                msg += "?\n" + "  ".join(out_help) + "\n"
            elif sel_modifier != "":
                out_help.append(["", "LINE", "", "Search Text"])
                msg += "?\n" + scripts.cli_command_exec.format_data(out_help)
            else:
                # print(cur_commands)
                for cc in cur_commands:
                    out_help.append(cc.replace("%W", "WORD"))
                msg += "?\n" + "  ".join(out_help) + "\n"

        return msg
    else:
        if temp_cmd != {} and not (temp_cmd[0].get("optional") or
                                   (temp_cmd[0].get("optional_on_no") and command_chain[0] == "no")):
            if curcmd == "":
                return ""
            else:
                return '% Incomplete command. Type "' + curcmd + '?" for a list of subcommands'
        else:
            if len(cur_commands) > 1:
                return "% Ambiguous command:  " + strinput
            else:
                return {"command": out_command, "function": last_func, "context": curcontext, "remains": leftovers,
                        "chain": command_chain}


def add_filters(input, output):
    """
    This function is designed to filter output when using include,
    exclude, etc.
    :param input: Raw output string
    :param output: Raw output from command
    :return: Filtered string
    """
    if "|" in input:
        newout = ""
        incmd = input.split("|")[1].strip()
        filterlist = incmd.split(" ")
        outlist = output.split("\n")
        # newout = outlist[0] + "\n"
        if filterlist[0] in ["i", "in", "inc", "incl", "inclu", "includ", "include"]:
            for o in outlist:
                # print(" ".join(filterlist[1:]).lower(), o.lower())
                if " ".join(filterlist[1:]).lower() in o.lower():
                    newout += o + "\n"
        elif filterlist[0] in ["e", "ex", "exc", "excl", "exclu", "exclud", "exclude"]:
            for o in outlist:
                if " ".join(filterlist[1:]).lower() not in o.lower():
                    newout += o + "\n"
        elif filterlist[0] in ["b", "be", "beg", "begi", "begin"]:
            foundbeg = False
            for o in outlist:
                if " ".join(filterlist[1:]).lower() in o.lower():
                    foundbeg = True
                if foundbeg:
                    newout += o + "\n"
        elif filterlist[0] in ["s", "se", "sec", "sect", "secti", "sectio", "section"]:
            foundbeg = False
            for o in outlist:
                filter_str = " ".join(filterlist[1:]).lower()
                if foundbeg and o.lower()[0:1] not in [" ", "!"]:
                    foundbeg = False
                # if o.lower()[0:len(filter_str)] == filter_str:
                if o.lower()[0:1] not in [" ", "!"] and filter_str in o.lower():
                    foundbeg = True
                if foundbeg:
                    newout += o + "\n"

        if newout[-2:] == "\n\n":
            return newout[0:-1]
        else:
            return newout
    return output


def main():
    curcontextdesc = "#"
    curcontext = "root"
    contextchain = [{"prompt": curcontextdesc, "contextname": curcontext, "elements": None, "selected": None, "selected_data": None}]

    bindings = KeyBindings()

    @bindings.add('?')
    def _(event):
        i = parse_input(session.app.current_buffer.text, contextchain[len(contextchain)-1]["contextname"], gethelp=True)
        print(i, end="")
        print("\n" + contextchain[len(contextchain)-1]["prompt"] + " " + session.app.current_buffer.text, end="")

    print('Welcome to the AdP Sync shell. Type help or ? to list commands.\n')
    session = PromptSession(history=FileHistory('.adp_cli_history'))
    while True:
        try:
            n = NestedCompleter(words_dic=join_contexts(contextchain[len(contextchain)-1]["contextname"]))
            text = session.prompt(contextchain[len(contextchain)-1]["prompt"] + " ", key_bindings=bindings, completer=n, complete_style=CompleteStyle.READLINE_LIKE)
        except KeyboardInterrupt:       # Ctrl-C
            continue
        except EOFError:                # Ctrl-D
            break
        else:
            pi = parse_input(text, contextchain[len(contextchain)-1]["contextname"])
            if pi != "":
                if isinstance(pi, dict) and pi["command"]:
                    fxn = pi.get("function")
                    execfx = getattr(scripts.cli_command_exec, fxn)
                    result, contextchain = execfx(pi, text, contextchain)
                    if result != "":
                        print(add_filters(text, result))
                    if contextchain == []:
                        exit()
                else:
                    print(pi)


if __name__ == '__main__':
    main()


def run():     # pragma: no cover
    main()
