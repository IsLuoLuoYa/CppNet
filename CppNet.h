#pragma once

// 记得-lpthread;
// vs远程调试：属性-> 链接器-> 所有选项 -> 附加依赖项-lpthread;
#ifndef _CPP_NET_H_
#define _CPP_NET_H_

#define _SILENCE_CXX17_RESULT_OF_DEPRECATION_WARNING
#define _CRT_SECURE_NO_WARNINGS

#ifdef _WIN64
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")
#include <Windows.h>
#include <direct.h>
#include <Winsock2.h>
#endif

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")
#include <Windows.h>
#include <direct.h>
#include <Winsock2.h>
#include <io.h>
#endif

#ifndef WIN32
#ifndef _WIN64
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <sys/ioctl.h>
#include <dirent.h>
#include <sys/signal.h>
#define SOCKET int
#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR            (-1)
#endif
#endif

#include<string.h>
#include <string>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <shared_mutex>
#include <map>
#include <unordered_map>
#include <vector>
#include <queue>
#include <condition_variable>
#include <functional>
#include <future>
#include <list>
#include <type_traits>
#include "google/protobuf/message.h"

static const int DEFAULTBUFFERLEN = 65536;

class CppNetStart
{
public:
	CppNetStart()
	{
#ifdef WIN32
		WORD sockVersion = MAKEWORD(2, 2);
		WSADATA wsdata;
		WSAStartup(sockVersion, &wsdata);
#else
		sigset_t set;
		if (-1 == sigemptyset(&set))
		{

		}
		if (-1 == sigaddset(&set, SIGPIPE))
		{

		}
		if (-1 == sigprocmask(SIG_BLOCK, &set, nullptr))
		{

		}

		signal(SIGHUP, [](int no) {});
		signal(SIGINT, [](int no) {});
		signal(SIGKILL, [](int no) {});
#endif // !WIN32
	}
};

class CSocketObj;
typedef std::function<void(CSocketObj*, void*, int)> MsgFunType;

struct CNetMsgHead
{
	int MdLen;		// 该包总长度
	int MdCmd;		// 该包执行的操作
	CNetMsgHead()
	{
		MdLen = sizeof(CNetMsgHead);
		MdCmd = -1;				// 该值为-1时默认为心跳包
	}
};
struct CNetMsg
{
	CNetMsgHead Head;
	const char* Data = nullptr;
};

class CTimer
{
private:
	std::chrono::time_point<std::chrono::high_resolution_clock>     MdBegin;

public:
	CTimer() { update(); }
	void update()                           /*更新为当前的时间点*/ { MdBegin = std::chrono::high_resolution_clock::now(); }
	double getElapsedSecond()               /*获取当前秒*/ { return  (double)getElapsedTimeInMicroSec() * 0.000001; }
	double getElapsedTimeInMilliSec()       /*获取毫秒*/ { return (double)this->getElapsedTimeInMicroSec() * 0.001; }
	long long getElapsedTimeInMicroSec()    /*获取微妙*/ { return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - MdBegin).count(); }
};

class Barrier
{
private:
	unsigned int					MdTarget = 0;
#ifdef WIN32
	std::atomic<unsigned int>		MdBarrier;
#else
	pthread_barrier_t				MdBarrier;
#endif // WIN32
public:
	~Barrier() {};
	void MfInit(int target)
	{
		MdTarget = target;
#ifdef WIN32
		MdBarrier = 0;
#else
		pthread_barrier_init(&MdBarrier, nullptr, MdTarget);
#endif // WIN
	}

	void MfWait()
	{
#ifdef WIN32
		++MdBarrier;
		while (MdBarrier.load() < MdTarget)
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
#else
		pthread_barrier_wait(&MdBarrier);
#endif // WIN32
	}
};

union CObj
{
	CObj* MdNext;
	char* MdData;
};

template <class T>
class CMemoryPool
{
private:
	int				MdObjectLen;			// 一个T类型对象的长度
	int				MdNumbers;				// 能分配多少个对象
	char* MdPPool;				// 整个内存池所占用的空间地址起点
	CObj* MdObjectLinkHead;		// 内存池被转化为链表后的链表头
	std::mutex		MdMtx;					// 使用该内存池时的锁
	int				MdLackCount;			// 内存池使用不足时计数
public:
	CMemoryPool(int numbers);
	~CMemoryPool();
	CMemoryPool(const CMemoryPool&) = delete;
	CMemoryPool& operator=(const CMemoryPool&) = delete;
	T* MfApplyMemory();			// 申请一块内存
	void	MfReturnMemory(T* obj);		// 归还一块内存
};

template <class T>
CMemoryPool<T>::CMemoryPool(int numbers) :MdObjectLen(0), MdNumbers(numbers), MdPPool(nullptr), MdLackCount(0)
{
	if (0 >= MdNumbers)								// 数量 没有被声明为正确的值话，就退出
	{
		return;
	}
	MdObjectLen = sizeof(T);				// 确定一个对象的长度
	if (8 > MdObjectLen)					// 兼容64位
	{
		printf("WARRING!\tmsg: MDObjectLen < 8，already set MDObjectLen is 8\n11");
		MdObjectLen = 8;
	}
	MdPPool = new char[(MdObjectLen + 1) * MdNumbers] { 0 };					// 申请对象池的空间		对象长度*数量
	// 这里要解释一下为了多申请1字节的空间
	// 在调用掉该对象从对象池中返回对象池时，可能会有内存池中没有内存可分配的情况
	// 此时的行为应该是用new来申请空间，然后返回内存
	// 为了区分返回的内存是由内存池还是new分配，在分配的内存前加1字节的标志
	// 因为在对象池在申请时所有字节都已经设0，所以这1字节的标志为0就代表是内存池分配
	// new时，主动把该标志设为1，这样归还对象时，根据该标志来执行不同的操作

	// 接下来把申请的对象池初始化成一个链表
	MdObjectLinkHead = (CObj*)(MdPPool + 1);
	CObj* temp = MdObjectLinkHead;
	for (int i = 0; i < MdNumbers; ++i)
	{
		temp->MdNext = (CObj*)((char*)MdObjectLinkHead + (i * (MdObjectLen + 1)));
		temp = (CObj*)((char*)MdObjectLinkHead + (i * (MdObjectLen + 1)));
	}
	((CObj*)(MdPPool + (MdNumbers - 1) * (MdObjectLen + 1)))->MdNext = nullptr;
}

template <class T>
CMemoryPool<T>::~CMemoryPool()
{
	if (!MdPPool)
		delete MdPPool;					// 释放对象池的空间
	MdPPool = nullptr;
}

template <class T>
T* CMemoryPool<T>::MfApplyMemory()
{
	char* ret = nullptr;
	std::unique_lock<std::mutex> lk(MdMtx);
	if (nullptr != MdObjectLinkHead)
	{
		ret = (char*)MdObjectLinkHead;
		MdObjectLinkHead = MdObjectLinkHead->MdNext;
		return (T*)ret;
	}
	else
	{
		lk.unlock();
		++MdLackCount;
		ret = new char[MdObjectLen + 1];
		ret[0] = 1;
		return (T*)(ret + 1);
	}
	return nullptr;
}

template <class T>
void CMemoryPool<T>::MfReturnMemory(T* obj)
{
	if (nullptr == obj)
		return;
	std::unique_lock<std::mutex> lk(MdMtx);
	//if (0 == *((char*)obj - 1))
	{
		if (nullptr == MdObjectLinkHead)
		{
			((CObj*)obj)->MdNext = nullptr;
			MdObjectLinkHead = (CObj*)obj;
		}
		else
		{
			((CObj*)obj)->MdNext = MdObjectLinkHead->MdNext;
			MdObjectLinkHead = (CObj*)obj;
		}
		return;
	}
	/*else
	{
		lk.unlock();
		delete[]((char*)obj - 1);
	}*/
}

template <class T>
class CObjectPool
{
private:
	CMemoryPool<T>	MdMemoryPool;
public:
	CObjectPool(int numbers) :MdMemoryPool(numbers) {};
	~CObjectPool() {};
	CObjectPool(const CObjectPool&) = delete;
	CObjectPool& operator=(const CObjectPool&) = delete;
	template <typename ...Arg>
	T* MfApplyObject(Arg... a);	// 申请一快内存并构造对象
	void	MfReturnObject(T* obj);		// 析构对象并归还内存
};

template <class T>
template <typename ...Arg>
T* CObjectPool<T>::MfApplyObject(Arg... arg)
{
	T* tmp = MdMemoryPool.MfApplyMemory();
	return new(tmp)T(arg...);
}

template <class T>
void CObjectPool<T>::MfReturnObject(T* obj)
{
	obj->~T();
	MdMemoryPool.MfReturnMemory(obj);
}


class CThreadPool
{
private:
	std::vector<std::thread>            MdPool;             // 线程池
	std::queue<std::function<void()>>   MdTasks;            // 提交的任务队列
	std::mutex                          MdQueueMutex;       // 队列的锁
	std::condition_variable             MdQueueCondition;   // 队列的条件变量
	std::atomic<bool>                   MdIsStop;           // 队列停止时使用
	int                                 MdCount = 0;
	std::mutex                          MdCountMutex;
public:
	CThreadPool() { MdIsStop = false; };
	~CThreadPool()
	{
		if (!MdIsStop)
			MfStop();
	}

	void MfStart(size_t threads = 5)
	{
		for (size_t i = 0; i < threads; ++i)
			MdPool.push_back(std::thread(&CThreadPool::MfTheadFun, this));
	}
	void MfStop()
	{
		MdIsStop = true;
		MdQueueCondition.notify_all();
		for (std::thread& worker : MdPool)
			worker.join();
	}

	bool MfIsStop() { return MdIsStop; };
private:
	void MfTheadFun()
	{
		while (1)
		{
			std::function<void()> task;     // 要执行的任务
			{
				std::unique_lock<std::mutex> lock(MdQueueMutex);
				MdQueueCondition.wait(lock, [this] { return this->MdIsStop || !this->MdTasks.empty(); });
				if (this->MdIsStop && this->MdTasks.empty())
					return;
				task = this->MdTasks.front();
				this->MdTasks.pop();
				{
					std::unique_lock<std::mutex> lock2(MdCountMutex);
					if (++MdCount > 20000)
					{
						MdCount = 0;
						std::queue<std::function<void()>>(MdTasks).swap(MdTasks);
					}
				}

			}
			task();
		}
	}
public:
	template<class F, class... Args>
	auto MfEnqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>
	{
		using return_type = typename std::result_of<F(Args...)>::type;

		auto task = std::make_shared<std::packaged_task<return_type()>>(
			std::bind(std::forward<F>(f), std::forward<Args>(args)...)
			);

		std::future<return_type> res = task->get_future();
		{
			std::unique_lock<std::mutex> lock(MdQueueMutex);
			MdTasks.emplace([task]() { (*task)(); });
		}
		MdQueueCondition.notify_one();
		return res;
	}
};

class CSecondBuffer
{
private:
	char* MdPBuffer = nullptr;		// 缓冲区指针
	int			MdBufferLen = -1;			// 缓冲区长度
	int			Mdtail = 0;
	std::mutex	MdMtx;						// 操作数据指针时需要的互斥元
public:
	CSecondBuffer(int bufferlen = DEFAULTBUFFERLEN);
	~CSecondBuffer();

	char* MfGetBufferP();	// 返回缓冲区原始指针以供操作

	bool MfDataToBuffer(const char* data, int len);		// 写数据到缓冲区
	bool MfSendMsg(CNetMsg* Msg);
	int MfBufferToSocket(SOCKET sock);					// 数据从 缓冲区 写到 套接字，返回值主要用于判断socket是否出错，出错条件是send或recv返回值<=0

	int		MfSocketToBuffer(SOCKET sock);		// 数据从 套接字 写到 缓冲区，返回值主要用于判断socket是否出错，出错条件是send或recv返回值<=0
	bool MfPopFrontMsg(char* Buff, int BuffLen);		// 弹出缓冲区中的第一条消息

private:
	bool MfSend(SOCKET sock, const char* buf, int len, int* ret);	// 封装SEND和RECV调用其非阻塞模式，并处理两个问题
	bool MfRecv(SOCKET sock, void* buf, int len, int* ret);			// 返回值用来区分ret值结果参数是否可用，如果为1表示ret的值应该被用于更新tail，反之则不应该更新
};

class CSocketObj
{
private:
	SOCKET				MdSock;					// socket
	int					MdThreadIndex;			// 当前socket对象位于线程的线程索引，哪个dispose线程，service用
	CSecondBuffer		MdPSendBuffer;			// 发送缓冲区
	CSecondBuffer		MdPRecvBuffer;			// 接收缓冲区
	CTimer				MdHeartBeatTimer;		// 心跳计时器
	char				MdIP[20];				// sock对端的地址
	int					MdPort;					// sock对端的地址
	int64_t				MdUid = 0;				// server用的uid
public:
	std::unordered_map<std::string, std::string> UserCustomData;		// 自定义数据
public:
	CSocketObj(SOCKET sock, int SendBuffLen = DEFAULTBUFFERLEN, int RecvBuffLen = DEFAULTBUFFERLEN);
	~CSocketObj();
public:
	SOCKET	MfGetSock() { return MdSock; }

	char*	MfGetRecvBufP()						/*返回接收缓冲区原始指针*/ { return MdPRecvBuffer.MfGetBufferP(); }

	int		MfRecv()							/*为该对象接收数据*/ { return MdPRecvBuffer.MfSocketToBuffer(MdSock); }
	int		MfSend()							/*为该对象发送数据*/ { return MdPSendBuffer.MfBufferToSocket(MdSock); }

	int64_t MfGetUid()							{ return MdUid; }
	void	MfSetUid(int64_t Uid)				{ MdUid = Uid; }

	void	MfSetPeerAddr(sockaddr_in* addr)	/*设置对端IP和端口*/ { MdPort = ntohs(addr->sin_port); strcpy(MdIP, inet_ntoa(addr->sin_addr)); }

	char*	MfGetPeerIP()						/*获取对端IP*/ { return MdIP; }
	int		MfGetPeerPort()						/*获取对端端口*/ { return MdPort; }

	void	MfSetThreadIndex(int index)			/*设置线程索引*/ { MdThreadIndex = index; }
	int		MfGetThreadIndex()					/*获取线程索引，哪个dispose线程，service用*/ { return MdThreadIndex; }
	
	bool	MfPopFrontMsg(char* Buff, int BuffLen)		/*第一条信息移出接收缓冲区*/ { return MdPRecvBuffer.MfPopFrontMsg(Buff, BuffLen); }

	void	MfHeartBeatUpDate()					/*更新心跳计时*/ { MdHeartBeatTimer.update(); }
	bool	MfHeartIsTimeOut(int seconds)		/*传入一个秒数，返回是否超过该值设定的时间*/ { return seconds < MdHeartBeatTimer.getElapsedSecond(); }

	int		MfClose()							/*关闭套接字*/
	{
#ifdef WIN32
		return closesocket(MdSock);
#else
		return close(MdSock);
#endif // def WIN32
	}


	bool	MfDataToBuffer(const char* data, int len)		/*压数据到发送缓冲区*/ { return MdPSendBuffer.MfDataToBuffer(data, len); }
	bool	MfSendMsg(int MsgId, const char* data, int len)
	{
		if (!data)
			return false;
		CNetMsg Msg;
		Msg.Head.MdCmd = MsgId;
		Msg.Head.MdLen = static_cast<int>(len + sizeof(CNetMsgHead));
		Msg.Data = data;
		return MdPSendBuffer.MfSendMsg(&Msg);
	}
	bool	MfSendMsg(int MsgId, const ::google::protobuf::Message* pMessage)
	{
		std::string Pkt = "";
		if (NULL != pMessage && !pMessage->SerializeToString(&Pkt))
			return false;

		CNetMsg Msg;
		Msg.Head.MdCmd = MsgId;
		Msg.Head.MdLen = static_cast<int>(Pkt.size() + sizeof(CNetMsgHead));
		Msg.Data = Pkt.c_str();
		return MdPSendBuffer.MfSendMsg(&Msg);
	}
};

struct ClientConf
{
	std::string			Linkname;
	std::string			Ip;
	unsigned short		port = 0;
	int					SecondBufferSendLen = DEFAULTBUFFERLEN;// 第二缓冲区长度
	int					SecondBufferRecvLen = DEFAULTBUFFERLEN;// 第二缓冲区长度
	int					RawSocketSendLen = 0;		// socket本身缓冲区长度
	int					RawSocketRecvLen = 0;		// socket本身缓冲区长度
};

class CClientLink
{
private:
	ClientConf				MdConf;
	CSocketObj*				MdClientSock = 0;	// 客户连接对象
	std::atomic<int>		MdIsConnect = 0;	// 表示是否连接成功	
	std::unordered_map<int, MsgFunType> MsgDealFuncMap;
	bool					SelfDealPkgHead;	// 创建者自己处理包头数据
private:
public:
	CClientLink(bool _SelfDealPkgHead = false): SelfDealPkgHead(_SelfDealPkgHead)  {};
	~CClientLink() { MfClose(); }
	int MfConnect(const char* ip, unsigned short port);	/*发起一个连接*/
	int MfClose();										/*关闭一个连接*/
	inline CSocketObj* GetScoketObj()					/*返回socket对象*/ { return MdClientSock; }
	SOCKET MfGetSocket()								/*返回描述符*/ { return MdClientSock->MfGetSock(); }
	std::string MfGetSerivceNmae()						/*返回当前服务的名称*/ { return MdConf.Linkname.c_str(); }
	int MfGetIsConnect()								/*当前服务是否连接*/ { return MdIsConnect.load(); }
	int MfRecv()										/*供服务管理者调用接收数据*/ { return MdClientSock->MfRecv(); }
	int MfSend()										/*供服务管理者调用发送数据*/ { return MdClientSock->MfSend(); }
	bool MfDataToBuffer(const char* data, int len)		/*供调用者插入数据，插入数据到发送缓冲区*/ { return MdClientSock->MfDataToBuffer(data, len); }
	bool MfSendMsg(int MsgId, const char* data, int len)/*发消息*/ { return MdClientSock->MfSendMsg(MsgId, data, len); }
	const char* MfGetRecvBufferP()						/*供使用者处理数据，取得接收缓冲区原始指针*/ { return MdClientSock->MfGetRecvBufP(); }
	bool MfPopFrontMsg(char* Buff, int BuffLen)								/*供使用者处理数据，第一条信息移出缓冲区*/ { return MdClientSock->MfPopFrontMsg(Buff, BuffLen); }

public:
	bool RegMsg(int MsgId, MsgFunType fun)
	{
		if (MsgDealFuncMap.find(MsgId) != MsgDealFuncMap.end())
			return false;
		MsgDealFuncMap[MsgId] = fun;
		return true;
	}

	virtual void MfVNetMsgDisposeFun(SOCKET sock, CSocketObj* Ser, CNetMsgHead* msg, std::thread::id& threadid)
	{
		auto Fun = MsgDealFuncMap.find(msg->MdCmd);
		if (Fun == MsgDealFuncMap.end())
		{									
			return;
		}

		if (SelfDealPkgHead)
			Fun->second(Ser, ((char*)msg) + sizeof(CNetMsgHead), static_cast<int>(msg->MdLen - sizeof(CNetMsgHead)));
		else
			Fun->second(Ser, msg, msg->MdLen);	
	}
};

class CClientLinkManage
{
private:
	std::unordered_map<std::string, CClientLink*>		MdClientLinkList;
	std::shared_mutex						MdClientLinkListMtx;
	std::atomic<int>						MdIsStart = 0;			// 收发线程是否启动，不启动时，不能添加连接，因为如果放在构造中启动线程是危险的
	Barrier									MdBarrier;				// 用于创建连接前的收发线程启动
	int										MdHeartSendInterval;	// 心跳发送时间间隔，单位秒
	CNetMsgHead								MdDefautHeartPacket;	// 默认的心跳包对象
	CTimer									MdHeartTime;			// 心跳计时器对象
	CThreadPool								MdThreadPool;

	int	MdPublicCacheLen;			// 每条处理线程一个公共缓冲区,处理数据取出时也是trylock,然后把消息写到这里
	char* MdPublicCache;			// 这样dispose线程就不会小概率卡住了
private:
public:
	CClientLinkManage(int HeartSendInterval = 3);
	~CClientLinkManage();
	void MfStart();													// 启动收发线程
	void MfStop();
	bool MfCreateAddLink(ClientConf Conf);		// 如果需要建立新的连接，就new一个ClientLink，同时记录连接的目标，然后加入列表是，设置client可用
	void MfCloseLink(std::string Linkname);							// 关闭某个连接
	bool MfSendMsg(std::string name, int MsgId, const char* data, int len);
public:
	bool MfLinkIsSurvive(std::string name);							// 某个服务是否活着
private:
	void MfSendThread();											// 发送线程，循环调用send，收发线程根据是否可用标志确定行为
	void MfRecvThread();											// 接收线程，循环调用recv，收发线程根据是否可用标志确定行为
public:
	bool RegMsg(std::string LinkName, int MsgId, MsgFunType fun);
};

typedef std::function<void()> OnCloseFunType;
struct ServiceConf
{
	std::string			Fun;	
	std::string			Ip;
	unsigned short		port = 0;
	int					MdServiceMaxPeoples = 10000;// 该服务的上限人数
	int					MdDisposeThreadNums = 1;	// 消息处理线程数
	int					MdHeartBeatTime = 300;		// 心跳时限，该时限内未收到消息默认断开，单位秒	
	int					SecondBufferSendLen = DEFAULTBUFFERLEN;// 第二缓冲区长度
	int					SecondBufferRecvLen = DEFAULTBUFFERLEN;// 第二缓冲区长度
	int					RawSocketSendLen = 0;		// socket本身缓冲区长度
	int					RawSocketRecvLen = 0;		// socket本身缓冲区长度
	bool				SelfDealPkgHead = 0;		// 是否自己处理包头
	OnCloseFunType*		OnCloseFun = nullptr;
};

class CServiceNoBlock
{
protected:
	SOCKET										MdListenSock;				// 监听套接字
	ServiceConf									MdConf;						// 各种参数
	CTimer										MdHeartBeatTestInterval;	// 心跳间隔检测用到的计时器
	std::vector<CObjectPool<CSocketObj>*>		Md_CSocketObj_POOL;			// 客户端对象的对象池
	std::unordered_map<SOCKET, CSocketObj*>*	MdPClientJoinList;			// 非正式客户端缓冲列表，等待加入正式列表，同正式客户列表一样，一个线程对应一个加入列表
	std::mutex*									MdPClientJoinListMtx;		// 非正式客户端列表的锁
	std::unordered_map<SOCKET, CSocketObj*>*	MdPClientFormalList;		// 正式的客户端列表，一个线程对应一个map[],存储当前线程的服务对象,map[threadid]找到对应map，map[threadid][socket]找出socket对应的数据
	std::shared_mutex*							MdPClientFormalListMtx;		// 为一MdPEachDisoposeThreadOfServiceObj[]添加sock时，应MdEachThreadOfMtx[].lock
	std::unordered_map<int64_t, CSocketObj*>*	MdPClientFormalList_LinkUid;// 每个CSocketObj用一个自增的uid来索引以下
	int*										MdLinkUidCount;				// 自增的uid
	std::unordered_map<SOCKET, CSocketObj*>*	MdClientLeaveList;			// 等待从正式列表中移除的缓冲列表
	std::mutex*									MdClientLeaveListMtx;		// 移除列表的锁
	CThreadPool*								MdThreadPool;
	bool										SelfDealPkgHead;			// 创建者自己处理包头数据
	
	std::unordered_map<int, MsgFunType>			MsgDealFuncMap;				// 注册的消息列表

	int					MdPublicCacheLen = 0;	// 每条处理线程一个公共缓冲区,处理数据取出时也是trylock,然后把消息写到这里
	std::vector<char*>	MdPublicCache;			// 这样dispose线程就不会小概率卡住了

	OnCloseFunType* OnCloseFun = nullptr;

protected:			// 用来在服务启动时，等待其他所有线程启动后，再启动Accept线程
	Barrier MdBarrier1;
protected:			// 这一组变量，用来在服务结束时，按accept recv dispose send的顺序来结束线程以保证不出错
	Barrier MdBarrier2;		// accept线程		和	recv线程			的同步变量		！！！！！在epoll中未被使用！！！！！
	Barrier MdBarrier3;		// recv线程			和	所有dispos线程		的同步变量
	Barrier MdBarrier4;		// send线程			和	dispose线程			的同步和前面不同，用屏障的概念等待多个线程来继续执行
public:
	CServiceNoBlock();
	virtual ~CServiceNoBlock();
	void Init();
	bool Mf_NoBlock_Start(ServiceConf Conf);		// 启动收发处理线程的非阻塞版本
	bool Mf_NoBlock_Stop();							// 遍历所有连接
	void VisitSocketObj(std::function<bool(CSocketObj*)> Fun);
	bool Mf_SendMsgByUid(int64_t Uid, int MsgId, char* Data, int len);
	void SetOncloseFun(OnCloseFunType* Fun) { OnCloseFun = Fun; }
protected:
	bool Mf_Init_ListenSock();		// 初始化套接字
private:
	void Mf_NoBlock_AcceptThread();									// 等待客户端连接的线程
	void Mf_NoBlock_RecvThread();									// 收线程
	void Mf_NoBlock_DisposeThread(int SeqNumber);					// 处理线程
	void Mf_NoBlock_SendThread();									// 发线程
	void Mf_NoBlock_ClientJoin(std::thread::id threadid, int SeqNumber);	// 客户端加入正式列表
	void Mf_NoBlock_ClientLeave(std::thread::id threadid, int SeqNumber);	// 客户端移除正式列表
public:
	bool RegMsg(int MsgId, MsgFunType fun)
	{
		if (MsgDealFuncMap.find(MsgId) != MsgDealFuncMap.end())
			return false;
		MsgDealFuncMap[MsgId] = fun;
		return true;
	}

	virtual void MfVNetMsgDisposeFun(SOCKET sock, CSocketObj* cli, CNetMsgHead* msg, std::thread::id& threadid)
	{
		auto Fun = MsgDealFuncMap.find(msg->MdCmd);
		if (Fun == MsgDealFuncMap.end())
		{											
			return;
		}


		if (SelfDealPkgHead)
			Fun->second(cli, ((char*)msg) + sizeof(CNetMsgHead), static_cast<int>(msg->MdLen - sizeof(CNetMsgHead)));
		else
			Fun->second(cli, msg, msg->MdLen);
	}
};

#ifndef WIN32

class CServiceEpoll :public CServiceNoBlock
{
private:
	std::vector<SOCKET>			MdEpoll_In_Fd;		// epoll句柄
	std::vector<epoll_event*>	MdEpoll_In_Event;	// 接收线程用到的结构集合
	int							MdThreadAvgPeoples;	// 每个线程的平均人数
public:
	CServiceEpoll();
	virtual ~CServiceEpoll();
	bool Mf_Epoll_Start(ServiceConf Conf);
	void Mf_Epoll_Stop();
private:
	void Mf_Epoll_AcceptThread();							// 等待客户端连接的线程
	void Mf_Epoll_RecvAndDisposeThread(int SeqNumber);		// 处理线程
	void Mf_Epoll_SendThread();								// 发线程
	void Mf_Epoll_ClientJoin(std::thread::id threadid, int SeqNumber);	// 客户端加入正式列表
	void Mf_Epoll_ClientLeave(std::thread::id threadid, int SeqNumber);	// 客户端移除正式列表
};

#endif // !WIN32

#endif