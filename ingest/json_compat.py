import orjson as _orjson


def loads(s, **kw):
    return _orjson.loads(s)


def dumps(obj, *, ensure_ascii=False, default=None, indent=None, **kw):
    opts = 0
    if indent:
        opts |= _orjson.OPT_INDENT_2
    if default:
        return _orjson.dumps(obj, default=default, option=opts).decode()
    return _orjson.dumps(obj, option=opts).decode()
