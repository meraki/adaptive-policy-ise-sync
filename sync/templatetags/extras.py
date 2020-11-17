import json

from django import template

register = template.Library()


@register.filter
def pretty_json(value):
    try:
        j = json.dumps(json.loads(value), indent=4)
    except Exception:
        j = value
    return j


@register.filter
def apikey(value):
    if value:
        showpart = value[-4:]
        outkey = ("*" * (len(value) - 4)) + showpart
        return outkey

    return value


@register.filter
def password(value):
    if value:
        outkey = "********"
        return outkey

    return value


@register.filter
def search(search_list, search_id):
    for sl in search_list:
        if sl["id"] == search_id:
            return sl["name"]
