# Assuming your Lambda handler is named `lambda_handler` in `lambda_function.py`
from lambda_function import lambda_handler

# Create a mock event
event = {
  "httpMethod": "GET",
  "path": "/doctors/all",
  "headers": {
    "Content-Type": "application/json"
  },
  "queryStringParameters": None  # Add this line; set to `None` or an empty dict `{}` if no query parameters
}

# Create a mock context
class Context:
    def __init__(self):
        self.function_name = "local_test"

# Invoke the handler
result = lambda_handler(event, Context())
print(result)
