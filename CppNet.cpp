#include "CppNet.h"

static CppNetStart Global_NewNetStartObj;

CSecondBuffer::CSecondBuffer(int bufferlen) :MdPBuffer(nullptr), MdBufferLen(-1), Mdtail(0)
{
	if (bufferlen <= 0)
		return;

	MdBufferLen = bufferlen;
	MdPBuffer = new char[MdBufferLen] {};
}

CSecondBuffer::~CSecondBuffer()
{
	if (MdPBuffer)
		delete[] MdPBuffer;
	MdPBuffer = nullptr;
}

char* CSecondBuffer::MfGetBufferP()
{
	return MdPBuffer;
}

bool CSecondBuffer::MfDataToBuffer(const char* data, int len)
{
	std::lock_guard<std::mutex> lk(MdMtx);
	if (Mdtail + len <= MdBufferLen)
	{
		memcpy(MdPBuffer + Mdtail, data, len);
		Mdtail += len;
		return true;
	}
	return false;
}

bool CSecondBuffer::MfSendMsg(CNetMsg* Msg)
{
	std::lock_guard<std::mutex> lk(MdMtx);
	if (Mdtail + Msg->Head.MdLen <= MdBufferLen)
	{
		int HeadLen = sizeof(Msg->Head);
		memcpy(MdPBuffer + Mdtail, &(Msg->Head), HeadLen);
		Mdtail += HeadLen;
		memcpy(MdPBuffer + Mdtail, Msg->Data, Msg->Head.MdLen - HeadLen);
		Mdtail += Msg->Head.MdLen - HeadLen;
		return true;
	}
	return false;
}

int CSecondBuffer::MfBufferToSocket(SOCKET sock)
{
	int ret = 0;
	std::unique_lock<std::mutex> lk(MdMtx, std::defer_lock);
	if (lk.try_lock())			// 锁定缓冲区
	{
		if (Mdtail > 0)			// 有数据时
		{
			if (MfSend(sock, MdPBuffer, Mdtail, &ret))			// ret值可用时
			{
				if (ret <= 0)									// 如果该值小于等于0，代表socket出错 或者 对端关闭，原样返回ret值
					return ret;
				Mdtail -= ret;									// 否则就是成功写入socket缓冲区，更新值
				memcpy(MdPBuffer, MdPBuffer + ret, Mdtail);		// 缓冲区中未被发送的数据移动到缓冲区起始位置
			}
		}
	}
	// 只有在成功锁定后 && 缓冲区有数据 && send返回值可用 同时成立的情况下
	// 才返回真实的ret，否则就是返回INT32_MAX，来表示没有出错，但是不代表接受了数据，只被调用者用于判断是否出错
	return INT32_MAX;
}

int CSecondBuffer::MfSocketToBuffer(SOCKET sock)
{
	// 没有出错时返回的值都是大于等于0的，但是返回值是INT32_MAX时，没有出错，但是也没有成功压入数据
	int ret = 0;
	std::unique_lock<std::mutex> lk(MdMtx, std::defer_lock);
	if (lk.try_lock())		// 锁定缓冲区
	{
		if (MdBufferLen - Mdtail > 0)		// 缓冲区又空间
		{
			if (MfRecv(sock, MdPBuffer + Mdtail, MdBufferLen - Mdtail, &ret))	// ret值可用时
			{
				if (ret <= 0)													// 如果该值小于等于0，代表socket出错 或者 对端关闭，原样返回ret值
					return ret;
				Mdtail += ret;													// 否则就是成功写入socket缓冲区，更新值
				return ret;
			}
		}
	}
	// 只有在成功锁定后 && 剩余空间大于0 && recv返回值可用 同时成立的情况下
	// 才返回真实的ret，否则就是返回INT32_MAX，来表示没有出错，但是不代表接受了数据，只被调用者用于判断是否出错
	return INT32_MAX;
}

bool CSecondBuffer::MfPopFrontMsg(char* Buff, int BuffLen)
{
	static int MSG_HEAD_LEN = sizeof(CNetMsgHead);
	std::unique_lock<std::mutex> lk(MdMtx, std::defer_lock);
	if (!lk.try_lock())
		return false;
	if (Mdtail <= MSG_HEAD_LEN)
		return false;
	int MsgLen = ((CNetMsgHead*)MdPBuffer)->MdLen;
	if (Mdtail < MsgLen)
		return false;
	if (BuffLen < MsgLen)
		return false;

	memcpy(Buff, MdPBuffer, MsgLen);
	int n = Mdtail - MsgLen;
	if (n >= 0)
	{
		memcpy(MdPBuffer, MdPBuffer + MsgLen, n);
		Mdtail = n;
	}
	return true;
}

bool CSecondBuffer::MfSend(SOCKET sock, const char* buf, int len, int* ret)
{
	*ret = (int)send(sock, buf, len, 0);
	if (0 <= *ret)					// 大于等于0时，要么对端正确关闭，要么发送成功，都使返回值可用，返回true
		return true;
	else							// 否则处理errno返回0，发送缓冲区满发送失败，被系统调用打断
	{
		if (0 == errno)
			return false;
		if (EWOULDBLOCK == errno)	// 非阻塞模式，socket发送缓冲区已满的情况，这种情况下，不是错误，返回false，ret值不应该被用于更新tail
			return false;
		if (EINTR == errno)			// 同样，EINTR不是错误，返回false，表示返回值不可用，ret值不应该被用于更新tail
			return false;

		// 这种情况下，返回值小于0，错误，ret值是send的返回值，返回false，ret值不可用，表示未解析的错误
		return false;
	}
}

bool CSecondBuffer::MfRecv(SOCKET sock, void* buf, int len, int* ret)
{
#ifndef WIN32
	* ret = (int)recv(sock, buf, len, 0);
#else
	* ret = recv(sock, (char*)buf, len, 0);
#endif // !WIN32

	if (0 <= *ret)				// 大于等于0时，要么错误正确接收，要么对端关闭，返回值都可用，返回true
		return true;
	else						// 否则处理recv被系统调用打断，非阻塞接收缓冲区空，以及errno为0的情况
	{
		if (0 == errno)
			return false;
		if (EWOULDBLOCK == errno)		// 非阻塞模式，socket接收缓冲区空的情况，这种情况下，不是错误，返回false，ret值不应该被用于更新tail或head
			return false;
		if (EINTR == errno)				// 同样，EINTR不是错误，返回false，返回值不可用，ret值不应该被用于更新tail或head
			return false;

		// 这种情况下，返回值小于0，错误，ret值是send的返回值，返回false，ret值不可用，表示未解析的错误
		return false;
	}
}

CSocketObj::CSocketObj(SOCKET sock, int SendBuffLen, int RecvBuffLen) :MdSock(sock), MdPSendBuffer(SendBuffLen), MdPRecvBuffer(RecvBuffLen)
{

}

CSocketObj::~CSocketObj()
{

}

int CClientLink::MfConnect(const char* ip, unsigned short port)
{
	auto Id = std::this_thread::get_id();
	int ret = -1;
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
#ifndef WIN32
	if (ip)		addr.sin_addr.s_addr = inet_addr(ip);
	else		addr.sin_addr.s_addr = INADDR_ANY;
#else
	if (ip)		addr.sin_addr.S_un.S_addr = inet_addr(ip);
	else		addr.sin_addr.S_un.S_addr = INADDR_ANY;
#endif


	SOCKET CliSock = socket(AF_INET, SOCK_STREAM, 0);
	if (SOCKET_ERROR == CliSock)
		return SOCKET_ERROR;

	for (int i = 0; i < 3; ++i)
	{
		ret = connect(CliSock, (sockaddr*)&addr, sizeof(sockaddr_in));
		if (SOCKET_ERROR == ret)
		{
			continue;
		}
		else
		{
#ifdef WIN32		
			unsigned long ul = 1;
			ioctlsocket(CliSock, FIONBIO, &ul);
#else
			int flags = fcntl(CliSock, F_GETFL, 0);
			fcntl(CliSock, F_SETFL, flags | O_NONBLOCK);
#endif
			if (MdConf.RawSocketRecvLen != 0)
				setsockopt(CliSock, SOL_SOCKET, SO_RCVBUF, (const char*)&(MdConf.RawSocketRecvLen), sizeof(int));
			if (MdConf.RawSocketSendLen != 0)
				setsockopt(CliSock, SOL_SOCKET, SO_SNDBUF, (const char*)&(MdConf.RawSocketSendLen), sizeof(int));

			MdClientSock = new CSocketObj(CliSock, MdConf.SecondBufferSendLen, MdConf.SecondBufferRecvLen);
			MdIsConnect = 1;
			break;
		}
	}
	return ret;
}

int CClientLink::MfClose()
{
	if (MdIsConnect)
	{
		MdIsConnect = 0;
		MdClientSock->MfClose();
	}

	if (nullptr != MdClientSock)
		delete MdClientSock;
	MdClientSock = nullptr;
	return 0;
}

CClientLinkManage::CClientLinkManage(int HeartSendInterval) :
	MdHeartSendInterval(HeartSendInterval),
	MdPublicCacheLen(1024 * 200)
{
	MdPublicCache = nullptr;
	MdPublicCache = new char[MdPublicCacheLen];
}

CClientLinkManage::~CClientLinkManage()
{
	if(!MdClientLinkList.empty())
		MfStop();

	if (nullptr != MdPublicCache)
		delete MdPublicCache;
	MdPublicCache = nullptr;
}

void CClientLinkManage::MfStart()
{
	MdBarrier.MfInit(3);
	MdThreadPool.MfStart(2);
	// 启动收发线程,需要做的是在启动收发线程前不应该建立连接
	MdThreadPool.MfEnqueue(std::bind(&CClientLinkManage::MfSendThread, this));
	MdThreadPool.MfEnqueue(std::bind(&CClientLinkManage::MfRecvThread, this));
	MdBarrier.MfWait();
	MdIsStart = 1;
}

void CClientLinkManage::MfStop()
{
	std::unique_lock<std::shared_mutex> lk(MdClientLinkListMtx);
	for (auto it = MdClientLinkList.begin(); it != MdClientLinkList.end();)
	{
		it->second->MfClose();
		MdClientLinkList.erase(it++);
	}
}

bool CClientLinkManage::MfCreateAddLink(ClientConf Conf)
{
	if (!MdIsStart.load())
		return false;

	{
		std::shared_lock<std::shared_mutex> lk(MdClientLinkListMtx);
		if (MdClientLinkList.find(Conf.Linkname) != MdClientLinkList.end())
			return false;
	}

	CClientLink* temp = new	CClientLink(Conf.Linkname);
	int ret = temp->MfConnect(Conf.Ip.c_str(), Conf.port);
	if (SOCKET_ERROR != ret)	// 成功连接后就加入正式队列
	{
		std::unique_lock<std::shared_mutex> lk(MdClientLinkListMtx);
		MdClientLinkList.insert(std::pair<std::string, CClientLink*>(Conf.Linkname, temp));
		return true;
	}
	delete temp;
	return false;
}

void CClientLinkManage::MfCloseLink(std::string Linkname)
{
	std::unique_lock<std::shared_mutex> lk(MdClientLinkListMtx);
	auto it = MdClientLinkList.find(Linkname);
	if (it != MdClientLinkList.end())
	{
		it->second->MfClose();
		MdClientLinkList.erase(it);
	}
}

bool CClientLinkManage::MfSendData(std::string name, const char* data, int len)
{
	auto it = MdClientLinkList.find(name);
	if (it == MdClientLinkList.end())
		return false;
	return it->second->MfDataToBuffer(data, len);
}

bool CClientLinkManage::MfSendMsg(std::string name, int MsgId, const char* data, int len)
{
	auto it = MdClientLinkList.find(name);
	if (it == MdClientLinkList.end())
		return false;
	return it->second->MfSendMsg(MsgId, data, len);
}

const char* CClientLinkManage::MfGetRecvBufferP(std::string name)
{
	auto it = MdClientLinkList.find(name);
	if (it == MdClientLinkList.end())
		return nullptr;
	return it->second->MfGetRecvBufferP();
}
bool CClientLinkManage::MfLinkIsSurvive(std::string name)
{
	std::shared_lock<std::shared_mutex> lk(MdClientLinkListMtx);
	auto it = MdClientLinkList.find(name);
	return it != MdClientLinkList.end() && it->second->MfGetIsConnect();
}

void CClientLinkManage::MfSendThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	MdBarrier.MfWait();

	// 主循环
	while (!MdThreadPool.MfIsStop())
	{
		// 为每个连接发送心跳包,这里是把心跳包加入第二缓冲区，之后一起由循环整个一起发送
		if (MdHeartTime.getElapsedSecond() > MdHeartSendInterval)
		{
			std::shared_lock<std::shared_mutex> lk(MdClientLinkListMtx);
			for (auto it = MdClientLinkList.begin(); it != MdClientLinkList.end(); ++it)
				it->second->MfDataToBuffer((const char*)&MdDefautHeartPacket, sizeof(CNetMsgHead));
			MdHeartTime.update();
		}

		// 加括号使锁提前释放
		{
			std::shared_lock<std::shared_mutex> lk(MdClientLinkListMtx);
			for (auto it = MdClientLinkList.begin(); it != MdClientLinkList.end(); ++it)
			{
				it->second->MfSend();		// 出错移除操作放在recv进程操作
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

void CClientLinkManage::MfRecvThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	MdBarrier.MfWait();

	// 主循环
	while (!MdThreadPool.MfIsStop())
	{
		{
			std::shared_lock<std::shared_mutex> lk(MdClientLinkListMtx);
			for (auto it = MdClientLinkList.begin(); it != MdClientLinkList.end();)
			{
				if (0 >= it->second->MfRecv())
				{
					std::unique_lock<std::shared_mutex> uk(MdClientLinkListMtx, std::adopt_lock);
					lk.release();		// 解除lk和互斥元的关联，这样lk析构时就不会第二次对互斥元解锁了
					it->second->MfClose();
					delete it->second;
					MdClientLinkList.erase(it++);
					continue;
				}

				while (it->second->MfPopFrontMsg(MdPublicCache, MdPublicCacheLen))
				{
					if (-1 == ((CNetMsgHead*)(it->second->MfGetRecvBufferP()))->MdCmd)	// 当该包的该字段为-1时，代表心跳
						it->second->GetScoketObj()->MfHeartBeatUpDate();
					else
						it->second->MfVNetMsgDisposeFun(it->second->MfGetSocket(), it->second->GetScoketObj(), (CNetMsgHead*)MdPublicCache, threadid);
				}
				++it;
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

bool CClientLinkManage::RegMsg(std::string LinkName, int MsgId, MsgFunType fun)
{
	std::shared_lock<std::shared_mutex> lk(MdClientLinkListMtx);
	auto Link = MdClientLinkList.find(LinkName);
	if (Link == MdClientLinkList.end())
		return false;
	return Link->second->RegMsg(MsgId, fun);
}

CServiceNoBlock::CServiceNoBlock() :
	MdPClientJoinList(nullptr),
	MdPClientJoinListMtx(nullptr),
	MdPClientFormalList(nullptr),
	MdPClientFormalList_LinkUid(nullptr),
	MdLinkUidCount(nullptr),
	MdPClientFormalListMtx(nullptr),
	MdClientLeaveList(nullptr),
	MdClientLeaveListMtx(nullptr),
	MdThreadPool(nullptr),
	MdPublicCacheLen(1024 * 200)
{

}

CServiceNoBlock::~CServiceNoBlock()
{
	if (MdThreadPool)
		delete MdThreadPool;
	MdThreadPool = nullptr;

	if (MdPClientFormalList)
		delete[] MdPClientFormalList;
	MdPClientFormalList = nullptr;

	if (MdPClientFormalList_LinkUid)
		delete[] MdPClientFormalList_LinkUid;
	MdPClientFormalList_LinkUid = nullptr;

	if (MdLinkUidCount)
		delete[] MdLinkUidCount;
	MdLinkUidCount = nullptr;

	if (MdPClientFormalListMtx)
		delete[] MdPClientFormalListMtx;
	MdPClientFormalListMtx = nullptr;

	if (MdPClientJoinList)
		delete[] MdPClientJoinList;
	MdPClientJoinList = nullptr;

	if (MdPClientJoinListMtx)
		delete[] MdPClientJoinListMtx;
	MdPClientJoinListMtx = nullptr;

	if (MdClientLeaveList)
		delete[] MdClientLeaveList;
	MdClientLeaveList = nullptr;

	if (MdClientLeaveListMtx)
		delete[] MdClientLeaveListMtx;
	MdClientLeaveListMtx = nullptr;

	for (auto& it : MdPublicCache)
		delete[] it;
	MdPublicCache.clear();
}

void CServiceNoBlock::Init()
{
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
		Md_CSocketObj_POOL.push_back(new CObjectPool<CSocketObj>(MdConf.MdServiceMaxPeoples / MdConf.MdDisposeThreadNums + 10));
	MdPClientFormalList = new std::unordered_map<SOCKET, CSocketObj*>[MdConf.MdDisposeThreadNums];
	MdPClientFormalList_LinkUid = new std::unordered_map<int64_t, CSocketObj*>[MdConf.MdDisposeThreadNums];
	MdLinkUidCount = new int[MdConf.MdDisposeThreadNums] {};
	MdPClientFormalListMtx = new std::shared_mutex[MdConf.MdDisposeThreadNums];
	MdPClientJoinList = new std::unordered_map<SOCKET, CSocketObj*>[MdConf.MdDisposeThreadNums];
	MdPClientJoinListMtx = new std::mutex[MdConf.MdDisposeThreadNums];
	MdClientLeaveList = new std::unordered_map<SOCKET, CSocketObj*>[MdConf.MdDisposeThreadNums];
	MdClientLeaveListMtx = new std::mutex[MdConf.MdDisposeThreadNums];
	MdThreadPool = new CThreadPool;
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
		MdPublicCache.push_back(new char[MdPublicCacheLen]);
}

bool CServiceNoBlock::Mf_NoBlock_Start(ServiceConf Conf)
{
	MdConf = Conf;
	Init();

	if (!Mf_Init_ListenSock())
		return false;

	// 处理线程同步
	MdBarrier1.MfInit(MdConf.MdDisposeThreadNums + 2 + 1);	// 处理线程数量 + send和recv线程 + recv线程本身
	MdBarrier2.MfInit(2);									// accept + recv两条线程
	MdBarrier3.MfInit(MdConf.MdDisposeThreadNums + 1);		// 处理线程数量 + recv线程
	MdBarrier4.MfInit(MdConf.MdDisposeThreadNums + 1);		// 处理线程数量 + send线程

	// 启动各个线程
	MdThreadPool->MfStart(1 + MdConf.MdDisposeThreadNums + 1 + 1);
	MdThreadPool->MfEnqueue(std::bind(&CServiceNoBlock::Mf_NoBlock_SendThread, this));			// 启动发送线程
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
		MdThreadPool->MfEnqueue(std::bind(&CServiceNoBlock::Mf_NoBlock_DisposeThread, this, i));	// 启动多条处理线程线程
	MdThreadPool->MfEnqueue(std::bind(&CServiceNoBlock::Mf_NoBlock_RecvThread, this));			// 启动接收线程
	MdThreadPool->MfEnqueue(std::bind(&CServiceNoBlock::Mf_NoBlock_AcceptThread, this));			// 启动等待连接线程

	return true;
}

bool CServiceNoBlock::Mf_NoBlock_Stop()
{
	MdThreadPool->MfStop();
	return true;
}

void CServiceNoBlock::VisitSocketObj(std::function<bool(CSocketObj*)> Fun)
{
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
	{
		bool Isbreak = false;
		std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);		
		for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
		{
			if (!Fun(it->second))
			{
				Isbreak = true;
				break;
			}
		}
		if (Isbreak)
			break;
	}
}

bool CServiceNoBlock::Mf_SendMsgByUid(int64_t Uid, int MsgId, char* Data, int len)
{
	int ThreadNums = Uid >> 32;
	std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[ThreadNums]);		// 锁住防止CSocketObj被移除列表析构
	auto SocketObj = MdPClientFormalList_LinkUid[ThreadNums].find(Uid);
	if (SocketObj == MdPClientFormalList_LinkUid[ThreadNums].end())
		return false;
	SocketObj->second->MfSendMsg(MsgId, Data, len);
}

bool CServiceNoBlock::Mf_Init_ListenSock()
{
	std::thread::id threadid = std::this_thread::get_id();

	// 初始化监听套接字
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(MdConf.port);
#ifndef WIN32
	if (!MdConf.Ip.empty())		addr.sin_addr.s_addr = inet_addr(MdConf.Ip.c_str());
	else						addr.sin_addr.s_addr = INADDR_ANY;
#else
	if (!MdConf.Ip.empty())		addr.sin_addr.S_un.S_addr = inet_addr(MdConf.Ip.c_str());
	else						addr.sin_addr.S_un.S_addr = INADDR_ANY;
#endif

	MdListenSock = socket(AF_INET, SOCK_STREAM, 0);
	if (SOCKET_ERROR == MdListenSock)
		return false;
	int reuse = 1;
	setsockopt(MdListenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(int));
	if (SOCKET_ERROR == bind(MdListenSock, (sockaddr*)&addr, sizeof(addr)))
		return false;
	if (SOCKET_ERROR == listen(MdListenSock, 100))
		return false;

	// 将接收套接字设为非阻塞，这里为了解决两个问题
	// 1是阻塞套接字，在整个服务程序退出时，如果没有客户端连接到来，会导致accept线程阻塞迟迟无法退出
	// 2是在unp第十六章非阻塞accept里，不过这个问题只在单线程情况下出现，就不写了
#ifndef WIN32														// 对套接字设置非阻塞
	int flags = fcntl(MdListenSock, F_GETFL, 0);
	fcntl(MdListenSock, F_SETFL, flags | O_NONBLOCK);
#else
	unsigned long ul = 1;
	ioctlsocket(MdListenSock, FIONBIO, &ul);
#endif
	return true;
}

void CServiceNoBlock::Mf_NoBlock_AcceptThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	// 接受连接时用到的数据
	SOCKET			sock;
	sockaddr_in		addr;			// 地址
	int				sizeofsockaddr = sizeof(sockaddr);
#ifndef WIN32
	socklen_t		len;			// 地址长度
#else
	int				len;			// 地址长度
#endif
	int				minPeoples = INT32_MAX;		// 存储一个最小人数
	int				minId = 0;					// 最小人数线程的Id
	int				currPeoples = 0;			// 当前已连接人数

	// 等待其他所有线程
	MdBarrier1.MfWait();

	// 主循环，每次循环接收一个连接
	while (!MdThreadPool->MfIsStop())
	{
		currPeoples = 0;
		for (int i = 0; i <= MdConf.MdDisposeThreadNums; ++i)	// 计算当前已连接人数
			currPeoples += (int)MdPClientFormalList[i].size();
		if (currPeoples > MdConf.MdServiceMaxPeoples)	// 大于上限服务人数，就不accpet，等待然后开始下一轮循环
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
			continue;
		}

		sock = INVALID_SOCKET;
		addr = {};
		len = sizeofsockaddr;
		sock = accept(MdListenSock, (sockaddr*)&addr, &len);
		if (SOCKET_ERROR == sock)
		{
			if (errno == 0 || errno == EWOULDBLOCK)			// windows非阻塞sock没有到达时errno是0，linux则是EWOULDBLOCK
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			/*else if (INVALID_SOCKET == sock)
				LogFormatMsgAndSubmit(threadid, WARN_FairySun, "accept return INVALID_SOCKET!");
			else
				LogFormatMsgAndSubmit(threadid, WARN_FairySun, "accept return ERROR!");*/
			continue;
		}
		else
		{
#ifndef WIN32												// 对收到套接字设置非阻塞
			int flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#else
			unsigned long ul = 1;
			ioctlsocket(sock, FIONBIO, &ul);
#endif
			if (MdConf.RawSocketRecvLen != 0)
				setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&(MdConf.RawSocketRecvLen), sizeof(int));
			if (MdConf.RawSocketSendLen != 0)
				setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&(MdConf.RawSocketSendLen), sizeof(int));

			minPeoples = INT32_MAX;
			for (int i = 0; i <= MdConf.MdDisposeThreadNums; ++i)	// 找出人数最少的
			{
				if (minPeoples > (int)MdPClientFormalList[i].size())
				{
					minPeoples = (int)MdPClientFormalList[i].size();
					minId = i;
				}
			}
			CSocketObj* TempSocketObj = Md_CSocketObj_POOL[minId]->MfApplyObject(sock, MdConf.SecondBufferSendLen, MdConf.SecondBufferRecvLen);
			TempSocketObj->MfSetPeerAddr(&addr);
			TempSocketObj->MfSetThreadIndex(minId);
			MdLinkUidCount[minId]++;
			if (MdLinkUidCount[minId] < 0)
				MdLinkUidCount[minId] = 1;
			int64_t Uid = MdLinkUidCount[minId] << 32;
			Uid |= MdLinkUidCount[minId];
			TempSocketObj->MfSetUid(Uid);
			std::lock_guard<std::mutex> lk(MdPClientJoinListMtx[minId]);								// 对应的线程map上锁
			MdPClientJoinList[minId].insert(std::pair<SOCKET, CSocketObj*>(sock, TempSocketObj));		// 添加该连接到加入缓冲区
		}
	}

	// 主循环结束后清理
#ifdef WIN32
	closesocket(MdListenSock);
#else
	close(MdListenSock);
#endif // WIN32

	MdBarrier2.MfWait();
}

void CServiceNoBlock::Mf_NoBlock_RecvThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	MdBarrier1.MfWait();

	int ret = 0;

	// 主循环
	while (!MdThreadPool->MfIsStop())
	{
		for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
		{
			std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);				// 对应的线程map上锁，放在这里上锁的原因是为了防止插入行为导致迭代器失效
			for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
			{
				ret = it->second->MfRecv();
				if (0 >= ret)				// 返回值小于等于0时表示socket出错或者对端关闭
				{
					std::unique_lock<std::mutex> lk(MdClientLeaveListMtx[i], std::defer_lock);		// 这里尝试锁定，而不是阻塞锁定，因为这里允许被跳过
					if (lk.try_lock())																// 每一轮recv或者send发现返回值<=0,都会尝试锁定，该连接加入待移除缓冲区
						MdClientLeaveList[i].insert(std::pair<SOCKET, CSocketObj*>(it->first, it->second));
				}
				else if (INT32_MAX != ret)	// 没有出错时返回的值都是大于等于0的，但是返回值是INT32_MAX时，没有出错，但是也没有成功压入数据，只有成功压入数据时才更新计时器
					it->second->MfHeartBeatUpDate();
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// 主循环结束后，首先等待accept线程的结束以及发来的通知
	MdBarrier2.MfWait();

	// 然后对所有套接字最后一次接收
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
	{
		std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);
		for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
			it->second->MfRecv();
	}


	// 接下来通知所有dispose线程
	MdBarrier3.MfWait();
}

void CServiceNoBlock::Mf_NoBlock_DisposeThread(int SeqNumber)
{
	std::thread::id threadid = std::this_thread::get_id();
	CTimer time;

	MdBarrier1.MfWait();

	// 主循环
	while (!MdThreadPool->MfIsStop())
	{
		if (time.getElapsedSecond() > 1)
		{
			Mf_NoBlock_ClientJoin(threadid, SeqNumber);		// 将待加入队列的客户放入正式
			Mf_NoBlock_ClientLeave(threadid, SeqNumber);		// 清理离开队列的客户端
			time.update();
		}

		// 遍历正式客户端列表处理所有消息
		{
			std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[SeqNumber]);
			for (auto it : MdPClientFormalList[SeqNumber])
			{
				while (it.second->MfPopFrontMsg(MdPublicCache[SeqNumber], MdPublicCacheLen))
				{
					if (-1 == ((CNetMsgHead*)MdPublicCache[SeqNumber])->MdCmd)	// 当该包的该字段为-1时，代表心跳
						it.second->MfHeartBeatUpDate();		// 更新心跳计时
					else
						MfVNetMsgDisposeFun(it.first, it.second, (CNetMsgHead*)MdPublicCache[SeqNumber], threadid);
					;
				}
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// 主循环结束后，所有处理线程都等待recv线程发来的通知
	MdBarrier3.MfWait();

	// 对所有套接字进行最后一次处理
	for (auto it : MdPClientFormalList[SeqNumber])
	{
		while (it.second->MfPopFrontMsg(MdPublicCache[SeqNumber], MdPublicCacheLen))
		{
			MfVNetMsgDisposeFun(it.first, it.second, (CNetMsgHead*)MdPublicCache[SeqNumber], threadid);
		}
	}

	MdBarrier4.MfWait();
}

void CServiceNoBlock::Mf_NoBlock_SendThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	MdBarrier1.MfWait();

	int ret = 0;

	// 主循环
	while (!MdThreadPool->MfIsStop())
	{
		for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
		{
			std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);			// 对应的线程map上锁，放在这里上锁的原因是为了防止插入行为导致迭代器失效
			for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
			{
				ret = it->second->MfSend();
				if (0 >= ret)
				{
					std::unique_lock<std::mutex> lk(MdClientLeaveListMtx[i], std::defer_lock);	// 这里尝试锁定，而不是阻塞锁定，因为这里允许被跳过
					if (lk.try_lock())															// 每一轮recv或者send发现返回值<=0,都会尝试锁定,总有一次能锁定他，将该连接加入待移除缓冲区
						MdClientLeaveList[i].insert(std::pair<SOCKET, CSocketObj*>(it->first, it->second));
				}
				//else if (INT32_MAX != ret)	// 没有出错时返回的值都是大于等于0的，但是返回值是INT32_MAX时，没有出错
				//	;
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// 主循环结束后，等待所有处理线程到达屏障,发送完所有数据，然后关闭所有套接字
	MdBarrier4.MfWait();

	// 发送所有数据
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
	{
		std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);
		for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
			it->second->MfSend();
	}

	// 关闭所有套接字
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
	{
		for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
		{
			it->second->MfClose();
			Md_CSocketObj_POOL[i]->MfReturnObject(it->second);
		}
	}
}

void CServiceNoBlock::Mf_NoBlock_ClientJoin(std::thread::id threadid, int SeqNumber)
{
	// 这个函数是客户端加入的，需要操作的，阻塞也是必然的
	std::lock_guard<std::mutex> lk(MdPClientJoinListMtx[SeqNumber]);
	if (!MdPClientJoinList[SeqNumber].empty())
	{
		std::lock_guard<std::shared_mutex> WriteLock(MdPClientFormalListMtx[SeqNumber]);
		for (auto it = MdPClientJoinList[SeqNumber].begin(); it != MdPClientJoinList[SeqNumber].end(); ++it)
		{
			MdPClientFormalList_LinkUid[SeqNumber][it->first] = it->second;
			MdPClientFormalList[SeqNumber][it->first] = it->second;
		}
		MdPClientJoinList[SeqNumber].clear();
	}
}

void CServiceNoBlock::Mf_NoBlock_ClientLeave(std::thread::id threadid, int SeqNumber)
{
	static const int HeartIntervalTime = MdConf.MdHeartBeatTime / 3;		// 心跳检测间隔时限

	// 本函数中的两个也都使用尝试锁，因为这里不是重要的地方，也不是需要高效执行的地方
	std::unique_lock<std::mutex> lk(MdClientLeaveListMtx[SeqNumber], std::defer_lock);
	std::unique_lock<std::shared_mutex> WriteLock(MdPClientFormalListMtx[SeqNumber], std::defer_lock);
	if (lk.try_lock() && WriteLock.try_lock())
	{
		// 第一个循环每隔 心跳超时时间的三分之一 检测一次心跳是否超时
		if (HeartIntervalTime < MdHeartBeatTestInterval.getElapsedSecond())
		{
			// 遍历当前列表的客户端心跳计时器，超时就放入待离开列表
			for (auto it : MdPClientFormalList[SeqNumber])
			{
				if (it.second->MfHeartIsTimeOut(MdConf.MdHeartBeatTime))
				{
					MdClientLeaveList[SeqNumber].insert(std::pair<SOCKET, CSocketObj*>(it.first, it.second));
				}

			}
		}

		// 第二个循环清除客户端
		if (!MdClientLeaveList[SeqNumber].empty())
		{
			for (auto it = MdClientLeaveList[SeqNumber].begin(); it != MdClientLeaveList[SeqNumber].end(); ++it)
			{
				if (OnCloseFun)
					(*OnCloseFun)();
				MdPClientFormalList[SeqNumber].erase(it->first);
				MdPClientFormalList_LinkUid[SeqNumber].erase(it->second->MfGetUid());
				it->second->MfClose();
				Md_CSocketObj_POOL[SeqNumber]->MfReturnObject(it->second);
			}
			MdClientLeaveList[SeqNumber].clear();
		}
	}
}

#ifndef WIN32
CServiceEpoll::CServiceEpoll() :
	CServiceNoBlock()
{
	MdThreadAvgPeoples = (MdConf.MdServiceMaxPeoples / MdConf.MdDisposeThreadNums) + 100;
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
	{
		MdEpoll_In_Event.push_back(new epoll_event[MdThreadAvgPeoples]);
	}
}

CServiceEpoll::~CServiceEpoll()
{
	for (auto it : MdEpoll_In_Event)
		delete[] it;
}

bool CServiceEpoll::Mf_Epoll_Start(ServiceConf Conf)
{
	MdConf = Conf;
	Init();

	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)		// 为各个处理线程建立epoll的描述符
	{
		MdEpoll_In_Fd.push_back(epoll_create(MdThreadAvgPeoples));
	}

	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)		// 检查各个描述符是否出错
	{
		if (-1 == MdEpoll_In_Fd[i])
		{

		}
	}

	if (!Mf_Init_ListenSock())
		return false;

	// 处理线程同步
	MdBarrier1.MfInit(MdConf.MdDisposeThreadNums + 1 + 1);	// 处理线程数量 + send和recv线程 + recv线程本身
	MdBarrier2.MfInit(2);								// 在epoll中未被使用
	MdBarrier3.MfInit(MdConf.MdDisposeThreadNums + 1);		// accept + 处理线程数量
	MdBarrier4.MfInit(MdConf.MdDisposeThreadNums + 1);		// 处理线程数量 + send线程

	MdThreadPool->MfStart(1 + MdConf.MdDisposeThreadNums + 1);
	MdThreadPool->MfEnqueue(std::bind(&CServiceEpoll::Mf_Epoll_SendThread, this));					// 启动发送线程
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
		MdThreadPool->MfEnqueue(std::bind(&CServiceEpoll::Mf_Epoll_RecvAndDisposeThread, this, i));	// 启动多条处理线程,！！！！收线程和处理线程合并了！！！！
	MdThreadPool->MfEnqueue(std::bind(&CServiceEpoll::Mf_Epoll_AcceptThread, this));		// 启动等待连接线程			
	return true;
}

void CServiceEpoll::Mf_Epoll_Stop()
{
	CServiceNoBlock::Mf_NoBlock_Stop();
}

void CServiceEpoll::Mf_Epoll_AcceptThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	// 接受连接时用到的数据
	SOCKET			sock;
	sockaddr_in		addr;			// 地址
	int				sizeofsockaddr = sizeof(sockaddr);
	socklen_t		len;			// 地址长度
	int				minPeoples = INT32_MAX;	// 存储一个最小人数
	int				minId = 0;					// 最小人数线程的Id
	int				currPeoples = 0;			// 当前已连接人数

	// 等待其他所有线程
	MdBarrier1.MfWait();

	// 主循环，每次循环接收一个连接
	while (!MdThreadPool->MfIsStop())
	{
		currPeoples = 0;
		for (int i = 0; i <= MdConf.MdDisposeThreadNums; ++i)	// 计算当前已连接人数
			currPeoples += (int)MdPClientFormalList[i].size();
		if (currPeoples > MdConf.MdServiceMaxPeoples)	// 大于上限服务人数，就不accpet，等待然后开始下一轮循环
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
			continue;
		}

		sock = INVALID_SOCKET;
		addr = {};
		len = sizeofsockaddr;
		sock = accept(MdListenSock, (sockaddr*)&addr, &len);
		if (SOCKET_ERROR == sock)
		{
			if (errno == 0 || errno == EWOULDBLOCK)		// windows非阻塞sock没有到达时errno是0，linux则是EWOULDBLOCK
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			/*else if (INVALID_SOCKET == sock)
				LogFormatMsgAndSubmit(threadid, WARN_FairySun, "accept return INVALID_SOCKET!");
			else
				LogFormatMsgAndSubmit(threadid, WARN_FairySun, "accept return ERROR!");*/
			continue;
		}
		else
		{
			int flags = fcntl(sock, F_GETFL, 0);					// 对收到套接字设置非阻塞
			fcntl(sock, F_SETFL, flags | O_NONBLOCK);

			if (MdConf.RawSocketRecvLen != 0)
				setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&(MdConf.RawSocketRecvLen), sizeof(int));
			if (MdConf.RawSocketSendLen != 0)
				setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&(MdConf.RawSocketSendLen), sizeof(int));

			minPeoples = INT32_MAX;
			for (int i = 0; i <= MdConf.MdDisposeThreadNums; ++i)			// 找出人数最少的
			{
				if (minPeoples > (int)MdPClientFormalList[i].size())
				{
					minPeoples = (int)MdPClientFormalList[i].size();
					minId = i;
				}
			}
			CSocketObj* TempSocketObj = Md_CSocketObj_POOL[minId]->MfApplyObject(sock, MdConf.SecondBufferSendLen, MdConf.SecondBufferRecvLen);
			TempSocketObj->MfSetPeerAddr(&addr);
			TempSocketObj->MfSetThreadIndex(minId);
			MdLinkUidCount[minId]++;
			if (MdLinkUidCount[minId] < 0)
				MdLinkUidCount[minId] = 1;
			int64_t Uid = MdLinkUidCount[minId] << 32;
			Uid |= MdLinkUidCount[minId];
			TempSocketObj->MfSetUid(Uid);
			std::lock_guard<std::mutex> lk(MdPClientJoinListMtx[minId]);								// 对应的线程map上锁
			MdPClientJoinList[minId].insert(std::pair<SOCKET, CSocketObj*>(sock, TempSocketObj));		// 添加该连接到加入缓冲区
		}
	}

	// 主循环结束后清理
#ifdef WIN32
	closesocket(MdListenSock);
#else
	close(MdListenSock);
#endif // WIN32
	MdBarrier3.MfWait();
}

void CServiceEpoll::Mf_Epoll_RecvAndDisposeThread(int SeqNumber)
{
	std::thread::id threadid = std::this_thread::get_id();
	CTimer time;

	MdBarrier1.MfWait();

	int Epoll_N_Fds;
	int ret = 0;
	SOCKET tmp_fd;
	CSocketObj* tmp_obj;

	// 主循环
	while (!MdThreadPool->MfIsStop())
	{
		if (time.getElapsedSecond() > 1)
		{
			Mf_Epoll_ClientJoin(threadid, SeqNumber);		// 将待加入队列的客户放入正式
			Mf_Epoll_ClientLeave(threadid, SeqNumber);		// 清理离开队列的客户端
			time.update();
		}

		// 遍历正式客户端列表处理所有消息
		{
			std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[SeqNumber]);
			Epoll_N_Fds = epoll_wait(MdEpoll_In_Fd[SeqNumber], MdEpoll_In_Event[SeqNumber], MdThreadAvgPeoples, 0);

			// 第一个循环对epoll返回的集合接收数据
			for (int j = 0; j < Epoll_N_Fds; ++j)
			{
				tmp_fd = MdEpoll_In_Event[SeqNumber][j].data.fd;
				tmp_obj = MdPClientFormalList[SeqNumber][tmp_fd];
				ret = tmp_obj->MfRecv();
				if (0 >= ret)				// 返回值小于等于0时表示socket出错或者对端关闭
				{
					std::unique_lock<std::mutex> lk(MdClientLeaveListMtx[SeqNumber], std::defer_lock);	// 这里尝试锁定，而不是阻塞锁定，因为这里允许被跳过
					if (lk.try_lock())																	// 每一轮recv或者send发现返回值<=0,都会尝试锁定
						MdClientLeaveList[SeqNumber].insert(std::pair<SOCKET, CSocketObj*>(tmp_fd, tmp_obj));
				}
				else if (INT32_MAX != ret)	// 没有出错时返回的值都是大于等于0的，但是返回值是INT32_MAX时，没有出错，但是也没有成功压入数据，只有成功压入数据时才更新计时器
					MdPClientFormalList[SeqNumber][tmp_fd]->MfHeartBeatUpDate();
			}

			// 第二个循环处理那些收到的数据
			for (int j = 0; j < Epoll_N_Fds; ++j)
			{
				tmp_fd = MdEpoll_In_Event[SeqNumber][j].data.fd;
				tmp_obj = MdPClientFormalList[SeqNumber][tmp_fd];
				while (tmp_obj->MfPopFrontMsg(MdPublicCache[SeqNumber], MdPublicCacheLen))
				{
					if (-1 == ((CNetMsgHead*)MdPublicCache[SeqNumber])->MdCmd)	// 当该包的该字段为-1时，代表心跳包
						tmp_obj->MfHeartBeatUpDate();		// 更新心跳计时
					else
						MfVNetMsgDisposeFun(tmp_fd, tmp_obj, (CNetMsgHead*)MdPublicCache[SeqNumber], threadid);
				}
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// 主循环结束后，所有处理线程都等待recv线程发来的通知
	MdBarrier3.MfWait();

	// 对所有套接字进行最后一次处理
	std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[SeqNumber]);
	Epoll_N_Fds = epoll_wait(MdEpoll_In_Fd[SeqNumber], MdEpoll_In_Event[SeqNumber], MdThreadAvgPeoples, 0);
	for (int j = 0; j < Epoll_N_Fds; ++j)
	{
		tmp_fd = MdEpoll_In_Event[SeqNumber][j].data.fd;
		tmp_obj = MdPClientFormalList[SeqNumber][tmp_fd];
		ret = tmp_obj->MfRecv();
		while (tmp_obj->MfPopFrontMsg(MdPublicCache[SeqNumber], MdPublicCacheLen))
		{
			MfVNetMsgDisposeFun(tmp_fd, tmp_obj, (CNetMsgHead*)MdPublicCache[SeqNumber], threadid);
		}
	}

	MdBarrier4.MfWait();
}

void CServiceEpoll::Mf_Epoll_SendThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	MdBarrier1.MfWait();

	int ret = 0;

	// 主循环
	while (!MdThreadPool->MfIsStop())
	{
		for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
		{
			std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);				// 对应的线程map上锁，放在这里上锁的原因是为了防止插入行为导致迭代器失效

			for (auto it : MdPClientFormalList[i])
			{
				ret = it.second->MfSend();
				if (0 >= ret)				// 返回值小于等于0时表示socket出错或者对端关闭
				{
					std::unique_lock<std::mutex> lk(MdClientLeaveListMtx[i], std::defer_lock);		// 这里尝试锁定，而不是阻塞锁定，因为这里允许被跳过
					if (lk.try_lock())																// 每一轮recv或者send发现返回值<=0,都会尝试锁定
						MdClientLeaveList[i].insert(std::pair<SOCKET, CSocketObj*>(it.first, it.second));
				}
				//else if (INT32_MAX != ret)	// 没有出错时返回的值都是大于等于0的，但是返回值是INT32_MAX时，没有出错，但是也没有成功压入数据，只有成功压入数据时才更新计时器
				//	;
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// 主循环结束后，等待所有处理线程到达屏障,发送完所有数据，然后关闭所有套接字
	MdBarrier4.MfWait();

	// 发送所有数据
	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
	{
		std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);
		for (auto it : MdPClientFormalList[i])
		{
			it.second->MfSend();
		}
	}

	for (int i = 0; i < MdConf.MdDisposeThreadNums; ++i)
	{
		for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
		{
			it->second->MfClose();
			Md_CSocketObj_POOL[i]->MfReturnObject(it->second);
		}
	}
}

void CServiceEpoll::Mf_Epoll_ClientJoin(std::thread::id threadid, int SeqNumber)
{
	epoll_event		EvIn{};
	EvIn.events = EPOLLIN;
	std::lock_guard<std::mutex> lk(MdPClientJoinListMtx[SeqNumber]);
	if (!MdPClientJoinList[SeqNumber].empty())
	{
		std::lock_guard<std::shared_mutex> WriteLock(MdPClientFormalListMtx[SeqNumber]);
		for (auto it = MdPClientJoinList[SeqNumber].begin(); it != MdPClientJoinList[SeqNumber].end(); ++it)
		{
			MdPClientFormalList_LinkUid[SeqNumber][it->first] = it->second;
			MdPClientFormalList[SeqNumber].insert(std::pair<SOCKET, CSocketObj*>(it->first, it->second));
			EvIn.data.fd = it->first;
			epoll_ctl(MdEpoll_In_Fd[SeqNumber], EPOLL_CTL_ADD, it->first, &EvIn);		// 设置套接字到收线程的Epoll
		}
		MdPClientJoinList[SeqNumber].clear();
	}
}

void CServiceEpoll::Mf_Epoll_ClientLeave(std::thread::id threadid, int SeqNumber)
{
	static const int HeartIntervalTime = MdConf.MdHeartBeatTime / 3;		// 心跳检测间隔时限

	// 本函数中的两个也都使用尝试锁，因为这里不是重要的地方，也不是需要高效执行的地方
	std::unique_lock<std::mutex> lk(MdClientLeaveListMtx[SeqNumber], std::defer_lock);
	std::unique_lock<std::shared_mutex> WriteLock(MdPClientFormalListMtx[SeqNumber], std::defer_lock);
	if (lk.try_lock() && WriteLock.try_lock())
	{
		// 第一个循环每隔 心跳超时时间的三分之一 检测一次心跳是否超时
		if (HeartIntervalTime < MdHeartBeatTestInterval.getElapsedSecond())
		{
			// 遍历当前列表的客户端心跳计时器，超时就放入待离开列表
			for (auto it : MdPClientFormalList[SeqNumber])
			{
				if (it.second->MfHeartIsTimeOut(MdConf.MdHeartBeatTime))
				{
					MdClientLeaveList[SeqNumber].insert(std::pair<SOCKET, CSocketObj*>(it.first, it.second));
				}
			}
		}

		// 第二个循环清除客户端
		if (!MdClientLeaveList[SeqNumber].empty())
		{
			for (auto it = MdClientLeaveList[SeqNumber].begin(); it != MdClientLeaveList[SeqNumber].end(); ++it)
			{
				if (OnCloseFun)
					(*OnCloseFun)();
				it->second->MfClose();
				epoll_ctl(MdEpoll_In_Fd[SeqNumber], EPOLL_CTL_DEL, it->first, nullptr);
				MdPClientFormalList[SeqNumber].erase(it->first);
				MdPClientFormalList_LinkUid[SeqNumber].erase(it->second->MfGetUid());
				Md_CSocketObj_POOL[SeqNumber]->MfReturnObject(it->second);
			}
			MdClientLeaveList[SeqNumber].clear();
		}
	}
}
#endif