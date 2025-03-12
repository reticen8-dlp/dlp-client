import subprocess
import json

# JSON data as a Python dictionary
json_data = [
    {
        "policy_id": "1b793657-742b-461f-8h11-6362f2e82987",
        "name": "Block File Upload",
        "description": "Prevents file uploads via browsers",
        "status": "Active",
        "severity": "High",
        "patterns": [
          {
            "id": "f18cd3e2-a867-40be-9937-26d92c28a79c",
            "name": "test",
            "type": {
              "keywords": ["bomb", "attack"],
              "regex": [
                "b(?P<card>(?:\\\\d{4}[- ]?){4})\\\\b",
                "serfresdf",
                "aerrfserfgse",
                "aewfserf",
                "erfser"
              ],
              "ML": []
            }
          }
        ],
        "files": [],
        "action": {
          "channel_action": {
            "network_channels": {
              "Email": {
                "action": "Allow",
                "included": ["network", "channel"],
                "excluded": ["email", "excluded"]
              },
              "FTP": {
                "action": "Block",
                "included": ["ftp", "channel"],
                "excluded": ["ftp", "excluded"]
              },
              "HTTP/S": {
                "action": "Allow",
                "included": ["abcd"],
                "excluded": ["efgh"]
              },
              "Chat": {
                "action": "Block",
                "included": ["ijkl"],
                "excluded": ["mnop"]
              },
              "Plaintext": {
                "action": "Allow",
                "included": ["qrstuv", "bbhdia"],
                "excluded": ["dakdfkal", "dfdkla"]
              }
            },
            "endpoint_channels": {
              "Apps": {
                "action": "Block",
                "included": ["dhjkl"],
                "excluded": ["dfghjk"]
              },
              "RemovableDrives": {
                "action": "Block",
                "included": ["*"],
                "excluded": [""]
              },
              "LocalDrives": {
                "action": "Allow",
                "included": ["D:\\"],
                "excluded": [""]
              },
              "Directories": {
                "action": "Allow",
                "included": ["qwertyu"],
                "excluded": ["vghjkl"]
              },
              "LAN": {
                "action": "Block",
                "included": ["dfghjk"],
                "excluded": ["cvbnm"]
              },
              "Bluetooth": { "action": "Block", "included": ["*"], "excluded": [] }
            }
          },
          "schedule": {
            "id": "7a36fc8d-e8cc-4942-9510-21f7dc785711",
            "cron_expression": None,
            "recurrence": "Weekly",
            "start_time": "2025-02-20T09:54:00",
            "end_time": "2025-02-20T17:53:00",
            "days_of_week": ["Monday","Tuesday" ,"Wednesday", "Thursday", "Saturday"]
          }
        }
      }
  ]

# Convert to JSON string
json_string = json.dumps(json_data)

# Path to your C++ executable
exe_path = "DiskControl.exe"

# Run the C++ executable and pass JSON data via stdin
try:
    result = subprocess.run(
        [exe_path],
        input=json_string,         # JSON data as input
        text=True,                 # Ensure input/output is treated as text
        capture_output=True        # Capture stdout and stderr
    )

    # Print the output from the C++ executable
    print("Output:", result.stdout)
    print("Errors:", result.stderr)

except Exception as e:
    print(f"Failed to run {exe_path}: {e}")
