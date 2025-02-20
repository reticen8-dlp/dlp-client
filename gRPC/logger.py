import grpc
import policy_pb2
import policy_pb2_grpc
from grpc_utils import get_grpc_channel

def send_log(client_id, agent_id, log_level, message):
    """ Sends log messages to the central logging server via gRPC """
    channel = get_grpc_channel()
    stub = policy_pb2_grpc.LogServiceStub(channel)  # FIXED: Correct service stub

    log_request = policy_pb2.LogRequest(
        client_id=client_id,
        agent_id=agent_id,
        log_level=log_level,
        message=message
    )
    try:
        response = stub.SendLog(log_request)
        if response.status == "Success":
            print(f"Log sent successfully: {message}")
        else:
            print(f"Log failed: {response.message}")
    except grpc.RpcError as e:
        print(f"Log RPC failed: {e.code()} - {e.details()}")