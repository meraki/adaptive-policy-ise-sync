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
