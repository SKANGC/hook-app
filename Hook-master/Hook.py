from utlis import print_msg, write_xlsx, resource_path
from utlis.simulate_click import SimulateClick
from utlis.device import get_frida_device
from multiprocessing import Process
from sys import exit
import multiprocessing
import traceback
import argparse
import random
import signal
import frida
import time
import sys
import os


try:
    import click
except:
    class click:
        @staticmethod
        def secho(message=None, **kwargs):
            print(message)

        @staticmethod
        def style(**kwargs):
            raise Exception("unsupported style")
try:
    from shutil import get_terminal_size as get_terminal_size
except:
    try:
        from backports.shutil_get_terminal_size import get_terminal_size as get_terminal_size
    except:
        pass


def frida_hook(device_info, app_name, use_module,
               wait_time=0, is_show=True, execl_file=None, isattach=False, external_script=None):
    """
    :param app_name: 包名
    :param use_module 使用哪些模块
    :param wait_time: 延迟hook，避免加壳
    :param is_show: 是否实时显示告警
    :param execl_file 导出文件
    :param isattach 使用attach hook
    :param external_script 加载外部脚本文件

    :return:
    """

    def my_message_handler(message, payload):  # 功能：处理从Frida脚本发送的消息
        """ 消息处理 """
        if message["type"] == "error":
            print(message)
            os.kill(os.getpid(), signal.SIGTERM)  # 终止当前进程
            return
        if message['type'] == 'send':
            data = message["payload"]  # 从消息中提取 payload 数据
            if data["type"] == "notice":  # 处理通知类型的消息
                alert_time = data['time']
                action = data['action']
                arg = data['arg']
                messages = data['messages']
                stacks = data['stacks']

                # 使用 tps.is_third_party(stacks) 检查堆栈是否属于第三方库
                subject_type = tps.is_third_party(stacks)

                if is_show:  # 如果 is_show 为真，则实时显示通知信息
                    print("------------------------------start---------------------------------")
                    print("[*] {0}，APP行为：{1}、行为主体：{2}、行为描述：{3}、传入参数：{4}".format(
                        alert_time, action, subject_type, messages, arg.replace('\r\n', '，')))
                    print("[*] 调用堆栈：")
                    print(stacks)
                    print("-------------------------------end----------------------------------")
                if execl_file:  # 如果指定了 execl_file，则将数据导出到 Excel 文件
                    global privacy_policy_status
                    global execl_data
                    execl_data.append({
                        'alert_time': alert_time,
                        'action': action,
                        'messages': messages,
                        'arg': arg,
                        'stacks': stacks,
                        'subject_type': subject_type,
                        'privacy_policy_status': "同意隐私政策" + privacy_policy_status.value,
                    })
            if data['type'] == "app_name":  # 处理应用名称消息
                get_app_name = data['data']
                # 获取应用名称并检查是否与当前应用名称匹配
                my_data = False if get_app_name == app_name else True
                script.post({"my_data": my_data})  # 将匹配结果发送回脚本
            if data['type'] == "isHook":  # 处理 Hook 状态消息
                global isHook
                isHook = True
                script.post({"use_module": use_module})  # 发送 use_module 信息回脚本
            if data['type'] == "noFoundModule":  # 处理未找到模块的消息
                print_msg('输入 {} 模块错误，请检查'.format(data['data']))
            if data['type'] == "loadModule":  # 处理加载模块的消息
                if data['data']:
                    print_msg('已加载模块{}'.format(','.join(data['data'])))
                else:
                    print_msg('无模块加载，请检查')  # 如果没有加载任何模块，打印提示消息，建议检查模块配置

    tps = device_info["thirdPartySdk"]  # 提取设备信息
    device = device_info["device"]
    try:
        pid = app_name if isattach else device.spawn([app_name])
        time.sleep(1)
        session = device.attach(pid)
        time.sleep(1)
        # 判断是加载外部脚本还是内置脚本 如果外部脚本路径不存在，使用内置脚本路径
        if external_script:  # external_script是一个函数参数，表示外部脚本文件的路径
            if os.path.isabs(external_script):  # 用于检查路径是否为绝对路径
                external_script = os.path.abspath(external_script)  # 将其转换为标准化的绝对路径
            else:
                # 将其与当前工作目录结合，形成一个绝对路径
                external_script = os.path.join(os.getcwd(), external_script)
        # 如果未提供外部脚本文件路径，则使用默认的script.js文件
        else:
            external_script = os.path.join(os.getcwd(), 'script.js')
        if os.path.isfile(external_script):  # 检查指定的外部脚本文件是否存在
            script_path = external_script
        else:  # 外部脚本文件不存在，则尝试使用内置的script.js文件
            script_path = resource_path('./script.js')
            not_exists_log = 'the external script file \'%s\' doesn\'t exists' % external_script
            if os.path.isfile(os.path.abspath(script_path)):
                # 如果内置脚本文件存在，则打印警告信息，指出外部脚本文件不存在，并继续加载内置脚本
                print('Warning: %s，loading built-in script...' % not_exists_log)
            else:
                print('Error: %s!' % not_exists_log)
                exit()
        # 读取脚本内容并追加延迟hook
        with open(script_path, encoding="utf-8") as f:
            script_read = f.read()
        if wait_time:
            script_read += "setTimeout(main, {0}000);\n".format(str(wait_time))
        else:
            script_read += "setImmediate(main);\n"
        # 创建和加载Frida脚本
        script = session.create_script(script_read)  # 创建一个新的Frida脚本对象
        # script_read是包含要执行的JavaScript代码的字符串，该字符串之前已经从文件中读取并可能添加了延迟执行的代码
        script.on("message", my_message_handler)  # 设置一个消息处理器，用于处理从Frida脚本发送的消息
        script.load()  # 加载并执行Frida脚本
        time.sleep(1)
        if not isattach:
            #  这一步骤是必要的，因为在spawn模式下，目标进程在启动后会被暂停，直到脚本加载完成
            device.resume(pid) # 用于恢复之前通过spawn方法启动的目标进程
        wait_time += 1
        time.sleep(wait_time)
        # 设置信号处理器：
        # 如果成功hook，设置信号处理器以处理终止信号。
        # 在接收到SIGINT或SIGTERM信号时，调用stop函数进行清理工作
        if isHook:   # 检查是否成功进行了 Hook 操作
            def stop(signum, frame):  # signum：信号编号  frame：当前堆栈帧
                print_msg('You have stoped hook.')
                session.detach()  # 分离当前的 Frida 会话，以释放资源
                if execl_file:
                    global execl_data  # 使用全局变量 execl_data，保存需要导出的数据
                    write_xlsx(execl_data, execl_file)
                exit()

            signal.signal(signal.SIGINT, stop)  # 将 SIGINT（通常由 Ctrl+C 触发）信号绑定到 stop 函数
            signal.signal(signal.SIGTERM, stop)  # 将 SIGTERM（终止信号）信号绑定到 stop 函数
            sys.stdin.read()  # 使程序阻塞等待，直到收到终止信号
        else:
            # 处理 Hook 失败的情况
            print_msg("hook fail, try delaying hook, adjusting delay time")
    # 以下是异常处理
    except frida.NotSupportedError as e:
        if 'unable to find application with identifier' in str(e):
            print_msg('找不到 {} 应用，请排查包名是否正确'.format(app_name))
        else:
            print_msg('frida-server没有运行/frida-server与frida版本不一致，请排查')
            print_msg(e)
    except frida.ProtocolError as e:
        print_msg('frida-server没有运行/frida-server与frida版本不一致，请排查')
        print_msg(e)
    except frida.ServerNotRunningError as e:
        print_msg('frida-server没有运行/没有连接设备，请排查')
        print_msg(e)
    except frida.ProcessNotFoundError as e:
        print_msg("找不到该进程，{}".format(str(e)))
    except frida.InvalidArgumentError as e:
        print_msg("script.js脚本错误，请排查")
        print_msg(e)
    except frida.InvalidOperationError as e:
        print_msg('hook被中断，是否运行其他hook框架(包括其他frida)，请排查')
    except frida.TransportError as e:
        print_msg('hook关闭或超时，是否运行其他hook框架(包括其他frida)/设备是否关闭selinux，请排查')
        print_msg(e)
    except KeyboardInterrupt:
        print_msg('You have stoped hook.')
    except Exception as e:
        print_msg("hook error")
        print(traceback.format_exc())
    finally:
        exit()


def agree_privacy(privacy_policy_status, device_id):
    # privacy_policy_status：用于记录隐私政策同意状态的对象
    # device_id：设备的唯一标识符，用于执行模拟点击操作
    try:
        # 等待应用启动
        time.sleep(5)
        screen_save_path = '/data/local/tmp'
        sc = SimulateClick(device_id, screen_save_path, 'screen.png')
        screencap_result = sc.run()  # 执行屏幕截图操作并获取结果
        if screencap_result:
            result = sc.get_result()
            while result == 1:
                sc = SimulateClick(device_id, screen_save_path, 'screen.png')
                sc.run()
                result = sc.get_result()
            if result == 2:
                # 如果 result 为 2（表示隐私政策已同意），则更新 privacy_policy_status.value 为 '后'
                privacy_policy_status.value = '后'
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    # 下面这句必须在if下面添加
    multiprocessing.freeze_support()  # 调用 multiprocessing.freeze_support() 以支持多进程模块冻结

    # 这里要移除上一次生成的，否则报错了会用上一次的截屏结果进行显示
    last_screen_shot = os.path.join(os.getcwd(), "screen.png")
    if not os.path.isfile(last_screen_shot):
        last_screen_shot = resource_path("screen.png")
    if os.path.isfile(last_screen_shot):
        os.remove(last_screen_shot)

    # show_banner()

    # 使用 argparse 模块定义和解析命令行参数，存储在 args 中
    parser = argparse.ArgumentParser(description="App privacy compliance testing.")
    parser.add_argument("package", help="APP_NAME or process ID ex: com.test.demo01 、12345")
    parser.add_argument("--time", "-t", default=0, type=int, help="Delayed hook, the number is in seconds ex: 5")
    parser.add_argument("--noshow", "-ns", required=False, action="store_const", default=True, const=False,
                        help="Showing the alert message")
    parser.add_argument("--file", "-f", metavar="<path>", required=False, help="Name of Excel file to write")
    parser.add_argument("--isattach", "-ia", required=False, action="store_const", default=False, const=True,
                        help="use attach hook")
    parser.add_argument("--noprivacypolicy", "-npp", required=False, action="store_const", default=False, const=True,
                        help="close the privacy policy. after closing, default status is agree privacy policy")

    module_group = parser.add_mutually_exclusive_group()
    module_group.add_argument("--use", "-u", required=False,
                              help="Detect the specified module,Multiple modules are separated by ',' ex:phone,permission")
    module_group.add_argument("--nouse", "-nu", required=False,
                              help="Skip specified module，Multiple modules are separated by ',' ex:phone,permission")

    parser.add_argument("--serial", "-s", required=False,
                        help="use device with given serial(device id), you can get it by exec 'adb devices'")
    parser.add_argument("--host", "-H", required=False,
                        help="connect to remote frida-server on HOST,ex:127.0.0.1:1234")
    parser.add_argument("--external-script", "-es", required=False,
                        help="load external frida script js, default: ./script.js")

    args = parser.parse_args()
    # 全局变量
    # 初始化全局变量，标识是否成功挂钩和存储 Excel 数据
    isHook = False
    execl_data = []

    # 如果用户指定了 --use 或 --nouse 参数，分别设置为检测或跳过的模块
    use_module = {"type": "all", "data": []}
    if args.use:
        use_module = {"type": "use", "data": args.use}
    if args.nouse:
        use_module = {"type": "nouse", "data": args.nouse}

    # 调用 get_frida_device() 函数获取设备信息，传入设备序列号或主机地址
    frida_device = get_frida_device(args.serial, args.host)
    # attach模式不调用同意隐私协议
    # 如果设置 --noprivacypolicy 或 --isattach 参数，标识隐私政策已同意，不启动进程。
    # 否则，启动一个新的进程来模拟点击同意隐私政策
    if args.noprivacypolicy or args.isattach:
        privacy_policy_status = multiprocessing.Value('u', '后')
        agree_privacy_process = None
    else:
        privacy_policy_status = multiprocessing.Value('u', '前')
        did = frida_device['did'] if frida_device['did'] else frida_device["device"].id
        agree_privacy_process = Process(target=agree_privacy, args=(privacy_policy_status, did))
        agree_privacy_process.daemon = True
        agree_privacy_process.start()

    process = int(args.package) if args.package.isdigit() else args.package
    # 调用 frida_hook() 函数传入参数
    frida_hook(frida_device, process, use_module,
               args.time, args.noshow, args.file, args.isattach, args.external_script)
