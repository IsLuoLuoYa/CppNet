# CppNet
一个只用包含头文件的cpp网络

需要c++17

跨平台

linux需要链接pthread

详细说明参考：https://blog.csdn.net/qq_43082206/article/details/110383165 在原始代码经过一些修改，主体部分未修改

Server:

	CServiceEpoll S1(6, 1000, 5);                // 心跳间隔 最多连接多少个 开几个线程分摊
	S1.Mf_Epoll_Start(0, 4567);                  // ip 和 端口 默认本机ip
	// or
	// CServiceNoBlock S2(6, 1000, 5);
	// S2.Mf_Epoll_Start(0, 4567);
	S1.RegMsg(200, [](CSocketObj* Cli, void* Data, int len)                // ser注册200号消息,发送100号回复客户端
		{
			// Deal
		Cli->MfSendMsg(100, (const char*)Data, len);
		});

Client:

	CClientLinkManage Cli;
	Cli.MfStart();
	std::string L1("t1");
	std::string L2("t2");
	Cli.MfCreateAddLink(L1, "192.168.56.101", 4567);       // 连接名字 ip 端口
	Cli.MfCreateAddLink(L2, "192.168.56.101", 4567);
	Cli.RegMsg(L1, 100, [](CSocketObj* Ser, void* Data, int len)             // cli收到100号消息处理 
		{
              // Deal
		});
	Cli.MfSendMsg(L1, 200, L1.c_str(), L1.size());                           // cli发送200号消息
