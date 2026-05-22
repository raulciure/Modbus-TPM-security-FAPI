import threading
from time import sleep


# exit_event = threading.Event()
exit_flag = False


def thread_function(param):
    while not exit_flag:
        print("The thread is working!")
        print("param = ", param)
        sleep(1)
    
    print("The thread is stopping!")


thread = threading.Thread(target=thread_function, args=(42,))
thread.start()

try:
    while thread.is_alive():
        print("exit_flag = ", exit_flag)
        sleep(1)
except KeyboardInterrupt:
    exit_flag = True

thread.join()

print("Thread closed successfully!")