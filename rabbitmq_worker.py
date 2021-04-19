import pika
import time
import subprocess
from pprint import pprint
import os
import sys
import shlex
 

# against connection closed exception of rabbitmq
for i in range(0, 1000):

    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host='localhost'
        
        #heartbeat=3600,
        #blocked_connection_timeout=3600
        ))
    channel = connection.channel()

    channel.queue_declare(queue='task_queue', durable=True)
    # print(' [*] Waiting for messages. To exit press CTRL+C')


    def callback(ch, method, properties, body):
        print(" [x] Received %r" % body.decode())
        # arguments=body.decode().split()
        arguments=shlex.split(body.decode())
        # pprint(arguments)

        process = subprocess.Popen(
                    ["/home/seclab/emulator-launch-local.sh",
                    arguments[0]], # example with 1 arg to shell
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
            # executable="/usr/bin/bash",

        out, err = process.communicate()
        return_code = process.poll()
        out = out.decode(sys.stdin.encoding)
        err = err.decode(sys.stdin.encoding)

        # print(out, err)

        with open("x.stdout","a+") as fd_stdout:
            fd_stdout.write(out)

        with open("x.stderr","a+") as fd_stderr:
            fd_stderr.write(err)


        print(" [x] Done")
        ch.basic_ack(delivery_tag=method.delivery_tag)


    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue='task_queue', on_message_callback=callback)


    # channel.start_consuming()

    try:
        channel.start_consuming()
    except Exception as e:
        print(e)