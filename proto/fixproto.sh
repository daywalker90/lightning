#!/bin/sh
../hold/bin/python -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. hold.proto primitives.proto
sed -i 's/^import .*_pb2 as/from . \0/' hold_pb2.py
sed -i 's/^import .*_pb2 as/from . \0/' hold_pb2_grpc.py
sed -i 's/^from pyln.grpc/from ./; s/ as / as /' node_pb2.py
sed -i 's/^from pyln.grpc/from ./; s/ as / as /' node_pb2_grpc.py
