# CppNet
一个只用包含头文件的cpp网络

需要c++17

linux需要链接pthread

详细说明参考：https://blog.csdn.net/qq_43082206/article/details/110383165 在原始代码经过一些修改，主体部分未修改

Server:

    ServiceConf Conf;
    Conf.Ip = "";
    Conf.port = 4567;
    CServiceEpoll S1();
	S1.Mf_Epoll_Start(Conf);
	//S1.Mf_NoBlock_Start(0, 4567);

    S1.RegMsg(200, [](CSocketObj* Cli, void* Data, int len)
        {
            printf("%s\n", Data);
            Cli->MfSendMsg(100, "bbbb", len);
        });

Client:

	CClientLinkManage Cli;
	Cli.MfStart();

	std::string L1("t1");
	std::string L2("t2");

	ClientConf Conf1;
	ClientConf Conf2;
	Conf1.Linkname = "t1";
	Conf1.Ip = "192.168.1.7";
	Conf1.port = 4567;

	Conf2.Linkname = "t2";
	Conf2.Ip = "192.168.1.7";
	Conf2.port = 4567;
	Cli.MfCreateAddLink(Conf1);
	Cli.MfCreateAddLink(Conf1);

	Cli.RegMsg(L1, 100, [](CSocketObj* Ser, void* Data, int len)
		{
			printf("%s\n", Data);
		});

	while(1)
	{
		Cli.MfSendMsg(L1, 200, "aaaaa\0", 5);
		Sleep(1000);
	}
