
from secureFlaskApp import app as application
import sys
import azure.functions as func
import os
import pathlib
root_function_dir = pathlib.Path(__file__).parent.parent
secureFlaskApp_path = os.path.join(root_function_dir, "secureFlaskApp")
sys.path.insert(0, secureFlaskApp_path)



def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    return func.WsgiMiddleware(application).handle(req, context)