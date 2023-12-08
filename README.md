# CppNet
一个只用包含头文件的cpp网络

需要c++17

linux需要链接pthread

详细说明参考：https://blog.csdn.net/qq_43082206/article/details/110383165 在原始代码经过一些修改，主体部分未修改

# 目前为止的缺点

虽然server的SocketObj对象用了对象池，但是SocketObj对象里还有两个SecondBuffer,这两个buffer本身的空间还是用new的，看起来不是那么好

各个线程之间遍历SocketObj的同步方式全部是tyr_lock，各个线程之间不会卡住，唯一会卡住的地方是SocketObj::MfSendMsg，不能让使用者发送失败，但是这个缓冲区又跨线程，如果增加一个重发机制还是需要加锁，暂时想不到好的解决办法，测了下在这个锁的地方等待时间也还行，win客户端连ubuntu虚拟机，1000个cli，每个连续发1000个14字节的数据包，测了10次，每次server在这个地方等待锁的总时间在200-300毫秒

# 例子
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

	ClientConf Conf1;
	ClientConf Conf2;
	Conf1.Linkname = "t1";
	Conf1.Ip = "192.168.1.7";
	Conf1.port = 4567;

	Conf2.Linkname = "t2";
	Conf2.Ip = "192.168.1.7";
	Conf2.port = 4567;
	Cli.MfCreateAddLink(Conf1);
	//Cli.MfCreateAddLink(Conf2);

	Cli.RegMsg(Conf1.Linkname, 100, [](CSocketObj* Ser, void* Data, int len)
		{
			printf("%s\n", Data);
		});

	while(1)
	{
		Cli.MfSendMsg(Conf1.Linkname, 200, "aaaaa\0", 5);
		Sleep(1000);
	}
