from sync.models import Task
from django.forms.models import model_to_dict


def run(model, operation, id=None):
    exclude = []
    outtxt = ""

    if model.upper() == "TASK":
        objs = Task.objects.all()
        exclude = ["task_data"]
    else:
        objs = []
        exit()

    if operation.upper() == "LIST":
        for obj in objs:
            new_dict = model_to_dict(obj)
            for ex in exclude:
                del new_dict[ex]
            new_dict["id"] = str(obj.id)

            print(new_dict)
    elif operation.upper() == "GET" and id:
        newobjs = objs.filter(id=id)
        for obj in newobjs:
            outtxt = ""
            new_dict = model_to_dict(obj)
            for ex in exclude:
                outtxt += new_dict[ex].replace("\\n", "\n")
                del new_dict[ex]

            print(obj)
            print(outtxt)
