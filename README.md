# hook-app
用于hook手机APP的各种API调用情况，用于检测APP是否调用敏感API
# 使用步骤
利用adb打开客户端的终端，并运行frida-server服务，模拟手机端打开frida-server：
 ![image](https://github.com/user-attachments/assets/b5ca48e9-db12-4033-ba53-f560dd752a3b)
 
服务器运行程序，检测到可连接设备：
 ![image](https://github.com/user-attachments/assets/5c80d2fa-04bf-466b-9f75-f4e459a5b092)
 
设备编号为1的设备即为目标设备，测试以视频APP——bilibili为目标，并尝试将监控日志写入excel文件：
 ![image](https://github.com/user-attachments/assets/8ef318b6-80f6-42cb-b3ec-2a20cb6a69e3)
 
为了测试方便，将监控日志输出到excel文件的同时也打印到控制台上，查看excel文件：
 ![image](https://github.com/user-attachments/assets/2c148194-cd9b-4d56-812f-c85995821527)
 
使用的手机模拟器为mumu模拟器，使用的frida-server可以在官网找到合适版本
