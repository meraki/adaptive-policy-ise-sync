import re
from scripts.ACEParser import ace_parser
import logging
import textwrap
import json
import datetime as dt


class WrappedFixedIndentingLog(logging.Formatter):
    converter = dt.datetime.fromtimestamp

    def __init__(self, fmt=None, datefmt=None, style='%', width=194, indent=4):
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)
        self.wrapper = textwrap.TextWrapper(width=width, subsequent_indent=' '*indent)

    def format(self, record: logging.LogRecord) -> str:
        arg_pattern = re.compile(r'%\((\w+)\)')
        arg_names = [x.group(1) for x in arg_pattern.finditer(self._fmt)]
        for field in arg_names:
            if field not in record.__dict__:
                record.__dict__[field] = None
            else:
                if len(str(record.__dict__[field])) > 16:
                    record.__dict__[field] = str(record.__dict__[field])[:16]

        return self.wrapper.fill(super().format(record))

    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = ct.strftime(datefmt)
        else:
            t = ct.strftime("%Y-%m-%d %H:%M:%S")
            s = "%s,%03d" % (t, record.msecs)
        return s


logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(WrappedFixedIndentingLog(
    '%(asctime)s %(levelname).1s %(function)-16s[%(lineno)-4s]  %(message)s', indent=41, datefmt='%M:%S.%f'))
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)


def lj(*args):
    flat_arg = ""
    for arg in args:
        flat_arg += str(arg) + " "

    return flat_arg     # str(args)


def search_data_for_fields(input_dict, field_names):
    # print("search_data_for_fields=", input_dict, field_names)
    for f in get_field_options(field_names):
        v = get_data_from_dict(input_dict, f)
        if v:
            return v

    return None


def get_field_options(field_names):
    return field_names.split(",")


def get_data_from_dict(input_dict, key_name):
    # print("get_data_from_dict=", input_dict, key_name)
    d_val = None
    # in this case we are using an extra processing function
    if "||" in key_name:
        k_lst = key_name.split("||")
        if k_lst[1] == "ACEParser":
            p_dat = input_dict.get(k_lst[0])
            if p_dat:
                d_val = []
                for p in p_dat.split("\n"):
                    ap_val = ace_parser.parseString(p).asDict()
                    # we always want this output to be a list
                    d_val.append(ap_val)
            else:
                d_val = None
    else:
        # otherwise just do a straight lookup
        d_val = input_dict.get(key_name)

    # print("get_data_from_dict=", d_val, type(d_val))
    return d_val


def normalize_objects(data_obj_query, rule_obj_query, generic_obj, element_type_query, advanced_mapping_query):
    e = {"function": "normalize_objects"}
    out_list = []

    for data_obj in data_obj_query:
        logger.debug(lj("=", data_obj), extra=e)
        out = {"origin": data_obj.element.elementtype.name}
        et_list = []
        for et in element_type_query:
            out[et.name] = {}
            et_list.append(et.name)
        src_data = {}
        dst_data = {}

        for k, v in data_obj.source_data.items():
            logger.debug(lj("==", k, v), extra=e)
            if k == "name" or k == "description":
                src_data[k] = generic_obj.get_data(k, safe=True)
                dst_data[k] = generic_obj.get_data(k, safe=True)
            else:
                new_k = k
                # new_src = data_obj.get_data(k, safe=False)
                # logger.debug(lj("===>", new_src, "<==="), extra=e)
                k_rule = rule_obj_query.filter(generictype=generic_obj.generictype).filter(field__contains=k).first()
                logger.debug(lj("===", k, k_rule), extra=e)
                if k_rule and k_rule.match:
                    src_data[k] = v
                    new_res = exec_rule(k, v, k_rule, generic_obj, advanced_mapping_query.filter(elementtype=data_obj.element.elementtype))
                    fld_list = k_rule.field.split(",")
                    logger.debug(lj("====", new_res, k, fld_list), extra=e)
                    if len(fld_list) == 1:
                        new_k = fld_list[0]
                    else:
                        for fld in fld_list:
                            if k in fld:
                                fld_list.remove(fld)
                        new_k = fld_list[0].split("||")[0]
                    # print("~~~", new_res, new_src, k_rule)
                    if new_res not in ("None", None):
                        dst_data[new_k] = new_res
                    logger.debug(lj("====", new_k, dst_data, data_obj), extra=e)

        # print("===")
        # print(json.dumps(src_data))
        # print(json.dumps(dst_data))
        # print("===")

        out[data_obj.element.elementtype.name] = src_data
        et_list.remove(data_obj.element.elementtype.name)
        out[et_list[0]] = dst_data

        missing = rule_obj_query.filter(generictype=generic_obj.generictype).filter(source_optional=True)
        logger.debug(lj("=missing", missing), extra=e)
        for m in missing:
            src = out[data_obj.element.elementtype.name].get(m.field)
            dst = out[et_list[0]].get(m.field)

            if not src and not dst:
                out[et_list[0]][m.field] = m.default_for_optional

        out_list.append(out)

    logger.debug(lj(json.dumps(out_list)), extra=e)
    return out_list


def exec_rule(key, value, rule_obj, generic_obj, advanced_mapping_query):
    e = {"function": "exec_rule"}
    # print("==exec_rule==", key, value, rule_obj, rule_obj.equivalence_mapping, rule_obj.match_type)
    result = None
    logger.debug(lj("*-", key, value, rule_obj, generic_obj, advanced_mapping_query), extra=e)
    if rule_obj.equivalence_mapping:
        logger.debug(lj("|  `--Branch 1"), extra=e)
        comp_list = rule_obj.equivalence_mapping.split("||")
        # since there can be multiple sets of equivalencies, we need to determine which one to use...
        for comp in comp_list:
            comp_vals = comp.split("=")
            # grp["objs"][0] represents (hopefully?) "source" object, so see if this is the group to use...
            if str(value) in comp_vals:
                comp_vals.remove(str(value))
                result = comp_vals[0]
                break
        logger.debug(lj("#-", key, value, result, comp_list), extra=e)
    elif rule_obj.match_type == "AdvancedMappingTable":
        logger.debug(lj("|  `--Branch 2"), extra=e)
        # Use the AdvancedMappingTable for translation... this is used for ACLs currently
        # print("value=", value)
        c = search_data_for_fields({key: value}, rule_obj.field)
        logger.debug(lj(key, value, rule_obj, rule_obj.field), extra=e)
        # print(key, value, rule_obj.field, c)
        # print("exec_rule", c)
        converted_rules, errors = exec_mapping_table(c, generic_obj, advanced_mapping_query)
        # print("exec_rule=", converted_rules)
        # if isinstance(converted_rules, (dict, list)):
        #     result = converted_rules
        # else:
        # print(converted_rules)
        # result = "\n".join(converted_rules)
        logger.debug(lj("#-", key, value, converted_rules, errors), extra=e)
        result = converted_rules
    else:
        logger.debug(lj("|  `--Branch 3"), extra=e)
        # not using equivalencies makes this process much simpler...
        result = value
        logger.debug(lj("#-", key, value, result), extra=e)

    # print("==exec_rule==", result)
    return result


def exec_mapping_table(object_rules, generic_obj, advanced_mapping_query):
    e = {"function": "exec_mapping_table"}
    # print(objects)
    bad_keys = []
    maps = advanced_mapping_query       # .exclude(json_key_1_ignored=True)
    # src_format = 0
    flatten_text = False
    out_rules = []
    # out_rule_required = []
    # for object_rules in objects:
    # out_obj_rules = []
    logger.debug(lj("*-", object_rules, maps), extra=e)
    for rule in object_rules:
        # print("==exec_mapping_table==rule::", rule)
        txt_flds = []
        # sel = None
        out_rule = {}
        for k, v in rule.items():
            obj = None
            # source and destination are different; need to convert
            rgx_test = maps.filter(json_key_1=str(k)).filter(json_val_1_regex=True)
            if len(rgx_test) > 0:
                for r in rgx_test:
                    if re.match(r.json_val_1, str(v)):
                        # print(r)
                        obj = r
                        break
            else:
                # d_k_dict = {"json_key_" + str(src_format): str(k)}           # + "__contains"
                # d_kv_dict = {"json_key_" + str(src_format): str(k) + "=" + str(v)}
                # d_v_dict = {"json_val_" + str(src_format): v}
                obj_kv = maps.filter(json_key_1=str(k)).filter(json_val_1=v)
                obj_eq = maps.filter(json_key_1=str(k) + "=" + str(v))       # Q(**d_k_dict)|Q(**d_kv_dict)
                obj_bs = maps.filter(json_val_1=v)
                obj_ls = maps.filter(json_key_1=k)      # last resort
                # print(k, v, obj_kv, obj_eq, obj_bs)
                # print(k, v, d_k_dict, d_kv_dict, d_v_dict)
                if len(obj_kv) > 0:
                    obj = obj_kv.first()
                elif len(obj_eq) > 0:
                    obj = obj_eq.first()
                elif len(obj_bs) > 0:
                    obj = obj_bs.first()
                elif len(obj_ls) > 0:
                    obj = obj_ls.first()
                else:
                    obj = None
                    logger.debug(lj("|--No Records", k, v), extra=e)
                    # print("--error--", k, v, len(obj_kv), len(obj_eq), len(obj_bs))
                    bad_keys.append({"error": "unrecognized attribute", "rule": rule, "key": k, "value": v})
                    continue

            logger.debug(lj("|--", k, v, len(obj_kv), len(obj_eq), len(obj_bs), len(obj_ls), obj,
                            obj.json_key_1_ignored, obj.json_key_2_ignored, obj.use_flat_text), extra=e)
            # print("==exec_mapping_table==obj::", k, v, obj)
            # print("==exec_mapping_table==", k, v, obj)
            if not obj:
                continue
            if not obj.json_key_1_ignored and not obj.json_key_2_ignored:
                # print(obj)
                # key_data = getattr(obj, "json_key_" + str(dst_format))
                # val_data = getattr(obj, "json_val_" + str(dst_format))
                # val_dst = getattr(obj, "json_val_" + str(dst_format))
                key_data = obj.json_key_2
                val_data = obj.json_val_2
                # print("====================", src_format, dst_format)
                # examples:
                #  dst_port_lower={{v1}},dst_port_upper={{v2}}
                #  src_port={{v1}}
                # print("==exec_mapping_table==", k, v, obj, key_data, val_data)
                if obj.use_flat_text:
                    logger.debug(lj("|  `--Branch 1"), extra=e)
                    flatten_text = True
                    val_data = obj.output_flat_text if obj.output_flat_text else ""
                    val_list = re.split(obj.json_val_1, str(v))
                    if "{{" in val_data:
                        for x in range(0, len(val_list)):
                            val_data = val_data.replace("{{v" + str(x) + "}}", str(val_list[x]))
                    if val_data != "":
                        txt_flds.append(val_data)
                elif "{{" in val_data and "=" in val_data:
                    logger.debug(lj("|  `--Branch 2"), extra=e)
                    val_list = re.split(obj.json_val_1, str(v))
                    for x in range(0, len(val_list)):
                        val_data = val_data.replace("{{v" + str(x) + "}}", str(val_list[x]))
                    vds = val_data.split(",")
                    for vd in vds:
                        kd_list = vd.split("=")
                        out_rule[kd_list[0]] = kd_list[1]
                elif "{{" in val_data:
                    logger.debug(lj("|  `--Branch 3", val_data), extra=e)
                    # print(val_dst, val_data)
                    val_src_list = obj.json_val_1.split(",")
                    for v_dst in range(0, len(val_src_list)):
                        repl_search = "{{v" + str(v_dst+1) + "}}"
                        repl_subst = rule.get(val_src_list[v_dst])
                        val_data = val_data.replace(repl_search, str(repl_subst))
                        logger.debug(lj("|   |--", v_dst, val_src_list[v_dst], val_data), extra=e)
                        # print("---", obj, repl_search, repl_subst, val_dst_list, key_data, val_data, val_dst)
                else:
                    logger.debug(lj("|  `--Branch 4"), extra=e)
                    out_rule[key_data] = val_data

                # logger.debug(lj(out_rule, flatten_text), extra=e)
                # handles case where the key is set to something like dst_oper=eq
                if key_data and "=" in key_data:
                    kd_list = key_data.split("=")
                    out_rule[kd_list[0]] = kd_list[1]
                else:
                    out_rule[key_data] = val_data

                # print(key_data, val_data, val_dst)
                # print("------------------")

            # if obj.json_key_2_required:
            #     print('hi')
            #     out_rule_required[getattr(obj, "json_key_" + str(src_format))] = \
            #         getattr(obj, "json_val_" + str(src_format) + "_default")

        # some elements require certain data elements; check for missing required keys and add defaults...
        # req_dict = {"json_key_" + str(src_format) + "_required": True}
        reqs = maps.filter(json_key_2_required=True)
        for req in reqs:
            # req_k = getattr(req, "json_key_" + str(src_format))
            # req_dv = getattr(req, "json_val_" + str(src_format) + "_default")
            req_k = req.json_key_2
            req_dv = req.json_val_2_default
            if req_k not in out_rule:
                out_rule[req_k] = req_dv

        if len(txt_flds) > 0:
            acl = " ".join(txt_flds)
            out_rules.append(acl)
        else:
            out_rules.append(out_rule)
    # if out_obj_rules:
    #     out_rules.append(out_obj_rules)
    # print("===========")
    # print(out_rules)
    # print(bad_keys)
    # print("===========")
    logger.debug(lj("#-", out_rules, flatten_text), extra=e)
    if flatten_text:
        return "\n".join(out_rules), bad_keys

    return out_rules, bad_keys
