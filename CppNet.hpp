#pragma once

// 记得-lpthread;
// vs远程调试：属性-> 链接器-> 所有选项 -> 附加依赖项-lpthread;

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
#include <vector>
#include <queue>
#include <condition_variable>
#include <functional>
#include <future>
#include <list>
#include <type_traits>

const int DEFAULTBUFFERLEN = 16384;

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

CppNetStart Global_NewNetStartObj;

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

std::string YearMonthDayHourMinuteSecondStr()
{
	const time_t t = time(NULL);
	struct tm Time;
#ifndef WIN32
	localtime_r(&t, &Time);
#else
	localtime_s(&Time, &t);
#endif
	char Temp[128];
	snprintf(Temp, 128, "%d-%d-%d_%d-%d-%d", Time.tm_year + 1900, Time.tm_mon + 1, Time.tm_mday, Time.tm_hour, Time.tm_min, Time.tm_sec);
	return Temp;
}

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
	CThreadPool() {};
	~CThreadPool()
	{
		MdIsStop = true;
		MdQueueCondition.notify_all();
		for (std::thread& worker : MdPool)
			worker.join();
	}

	void MfStart(size_t threads = 5)
	{
		for (size_t i = 0; i < threads; ++i)
			MdPool.push_back(std::thread(&CThreadPool::MfTheadFun, this));
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
	CSecondBuffer();
public:
	CSecondBuffer(int bufferlen = DEFAULTBUFFERLEN);
	~CSecondBuffer();

	char* MfGetBufferP();	// 返回缓冲区原始指针以供操作

	bool MfDataToBuffer(const char* data, int len);		// 写数据到缓冲区
	bool MfSendMsg(CNetMsg* Msg);
	int MfBufferToSocket(SOCKET sock);					// 数据从 缓冲区 写到 套接字，返回值主要用于判断socket是否出错，出错条件是send或recv返回值<=0

	int MfSocketToBuffer(SOCKET sock);		// 数据从 套接字 写到 缓冲区，返回值主要用于判断socket是否出错，出错条件是send或recv返回值<=0
	bool MfHasMsg();						// 缓冲区中是否够一条消息的长度
	void MfPopFrontMsg();					// 弹出缓冲区中的第一条消息
	void MfBufferPopData(int len);			// 缓冲区中数据弹出

private:
	bool MfSend(SOCKET sock, const char* buf, int len, int* ret);	// 封装SEND和RECV调用其非阻塞模式，并处理两个问题
	bool MfRecv(SOCKET sock, void* buf, int len, int* ret);			// 返回值用来区分ret值结果参数是否可用，如果为1表示ret的值应该被用于更新tail，反之则不应该更新
};

CSecondBuffer::CSecondBuffer() :MdPBuffer(nullptr), MdBufferLen(-1), Mdtail(0)
{
	MdBufferLen = DEFAULTBUFFERLEN;
	MdPBuffer = new char[MdBufferLen] {};
}

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

bool CSecondBuffer::MfHasMsg()
{
	static int MSG_HEAD_LEN = sizeof(CNetMsgHead);
	if (Mdtail >= MSG_HEAD_LEN)
		return Mdtail >= ((CNetMsgHead*)MdPBuffer)->MdLen;
	return false;
}

void CSecondBuffer::MfPopFrontMsg()
{
	if (MfHasMsg())
		MfBufferPopData(((CNetMsgHead*)MdPBuffer)->MdLen);
}

void CSecondBuffer::MfBufferPopData(int len)
{
	std::lock_guard<std::mutex> lk(MdMtx);
	int n = Mdtail - len;
	//printf("tail:%d, len:%d\n", Mdtail, len);
	if (n >= 0)
	{
		memcpy(MdPBuffer, MdPBuffer + len, n);
		Mdtail = n;
	}
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

class CSocketObj
{
private:
	SOCKET				MdSock;					// socket
	int					MdThreadIndex;			// 当前socket对象位于线程的线程索引，哪个dispose线程，service用
	CSecondBuffer* MdPSendBuffer;			// 发送缓冲区
	CSecondBuffer* MdPRecvBuffer;			// 接收缓冲区
	CTimer* MdHeartBeatTimer;		// 心跳计时器
	char				MdIP[20];				// sock对端的地址
	int					MdPort;					// sock对端的地址
public:
	CSocketObj(SOCKET sock, int SendBuffLen = DEFAULTBUFFERLEN, int RecvBuffLen = DEFAULTBUFFERLEN);
	~CSocketObj();
public:
	SOCKET	MfGetSock() { return MdSock; }

	char* MfGetRecvBufP()						/*返回接收缓冲区原始指针*/ { return MdPRecvBuffer->MfGetBufferP(); }

	int		MfRecv()							/*为该对象接收数据*/ { return MdPRecvBuffer->MfSocketToBuffer(MdSock); }
	int		MfSend()							/*为该对象发送数据*/ { return MdPSendBuffer->MfBufferToSocket(MdSock); }

	void	MfSetPeerAddr(sockaddr_in* addr)	/*设置对端IP和端口*/ { MdPort = ntohs(addr->sin_port); strcpy(MdIP, inet_ntoa(addr->sin_addr)); }

	char* MfGetPeerIP()						/*获取对端IP*/ { return MdIP; }
	int		MfGetPeerPort()						/*获取对端端口*/ { return MdPort; }

	void	MfSetThreadIndex(int index)			/*设置线程索引*/ { MdThreadIndex = index; }
	int		MfGetThreadIndex()					/*获取线程索引，哪个dispose线程，service用*/ { return MdThreadIndex; }

	bool	MfHasMsg()							/*接收缓冲区是否有消息*/ { return MdPRecvBuffer->MfHasMsg(); }
	void	MfPopFrontMsg()						/*第一条信息移出接收缓冲区*/ { MdPRecvBuffer->MfPopFrontMsg(); }

	void	MfHeartBeatUpDate()					/*更新心跳计时*/ { MdHeartBeatTimer->update(); }
	bool	MfHeartIsTimeOut(int seconds)		/*传入一个秒数，返回是否超过该值设定的时间*/ { return seconds < MdHeartBeatTimer->getElapsedSecond(); }

	int		MfClose()							/*关闭套接字*/
	{
#ifdef WIN32
		return closesocket(MdSock);
#else
		return close(MdSock);
#endif // def WIN32
	}


	bool	MfDataToBuffer(const char* data, int len)		/*压数据到发送缓冲区*/ { return MdPSendBuffer->MfDataToBuffer(data, len); }
	bool	MfSendMsg(int MsgId, const char* data, int len)
	{
		CNetMsg Msg;
		Msg.Head.MdCmd = MsgId;
		Msg.Head.MdLen = len + sizeof(CNetMsgHead);
		Msg.Data = data;
		return MdPSendBuffer->MfSendMsg(&Msg);
	}
};

CSocketObj::CSocketObj(SOCKET sock, int SendBuffLen, int RecvBuffLen) :MdSock(sock), MdPSendBuffer(nullptr), MdPRecvBuffer(nullptr), MdHeartBeatTimer(nullptr)
{
	MdPSendBuffer = new CSecondBuffer(SendBuffLen);
	MdPRecvBuffer = new CSecondBuffer(RecvBuffLen);
	MdHeartBeatTimer = new CTimer();
}

CSocketObj::~CSocketObj()
{
	if (MdPSendBuffer)
		delete MdPSendBuffer;
	MdPSendBuffer = nullptr;
	if (MdPRecvBuffer)
		delete MdPRecvBuffer;
	MdPRecvBuffer = nullptr;
	if (MdHeartBeatTimer)
		delete MdHeartBeatTimer;
	MdHeartBeatTimer = nullptr;
}

class CClientLink
{
private:
	std::string				MdLinkName;			// 服务名称，内容
	CSocketObj* MdClientSock = 0;	// 客户连接对象
	std::atomic<int>		MdIsConnect = 0;	// 表示是否连接成功	
	std::map<int, MsgFunType> MsgDealFuncMap;
private:
public:
	CClientLink(std::string s) {};
	~CClientLink() { MfClose(); }
	int MfConnect(const char* ip, unsigned short port);	/*发起一个连接*/
	int MfClose();										/*关闭一个连接*/
	inline CSocketObj* GetScoketObj()					/*返回socket对象*/ { return MdClientSock; }
	SOCKET MfGetSocket()								/*返回描述符*/ { return MdClientSock->MfGetSock(); }
	std::string MfGetSerivceNmae()						/*返回当前服务的名称*/ { return MdLinkName.c_str(); }
	int MfGetIsConnect()								/*当前服务是否连接*/ { return MdIsConnect.load(); }
	int MfRecv()										/*供服务管理者调用接收数据*/ { return MdClientSock->MfRecv(); }
	int MfSend()										/*供服务管理者调用发送数据*/ { return MdClientSock->MfSend(); }
	bool MfDataToBuffer(const char* data, int len)		/*供调用者插入数据，插入数据到发送缓冲区*/ { return MdClientSock->MfDataToBuffer(data, len); }
	bool MfSendMsg(int MsgId, const char* data, int len)/*发消息*/ { return MdClientSock->MfSendMsg(MsgId, data, len); }
	const char* MfGetRecvBufferP()						/*供使用者处理数据，取得接收缓冲区原始指针*/ { return MdClientSock->MfGetRecvBufP(); }
	bool MfHasMsg()										/*供使用者处理数据，缓冲区是否有消息*/ { return MdClientSock->MfHasMsg(); }
	void MfPopFrontMsg()								/*供使用者处理数据，第一条信息移出缓冲区*/ { MdClientSock->MfPopFrontMsg(); }

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
			return;

		Fun->second(Ser, ((char*)msg) + sizeof(CNetMsgHead), msg->MdLen - sizeof(CNetMsgHead));
	}
};

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
			MdClientSock = new CSocketObj(CliSock);
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

class CClientLinkManage
{
private:
	std::map<std::string, CClientLink*>		MdClientLinkList;
	std::shared_mutex						MdClientLinkListMtx;
	std::atomic<int>						MdIsStart = 0;			// 收发线程是否启动，不启动时，不能添加连接，因为如果放在构造中启动线程是危险的
	Barrier* MdBarrier;				// 用于创建连接前的收发线程启动
	int										MdHeartSendInterval;	// 心跳发送时间间隔，单位秒
	CNetMsgHead* MdDefautHeartPacket;	// 默认的心跳包对象
	CTimer* MdHeartTime;			// 心跳计时器对象
	CThreadPool								MdThreadPool;
private:
	bool MfSendData(std::string str, const char* data, int len);	// 发送数据，插入缓冲区
public:
	CClientLinkManage(int HeartSendInterval = 3);
	~CClientLinkManage();
	void MfStart();													// 启动收发线程
	int MfCreateAddLink(std::string Linkname, const char* ip, unsigned short port);		// 如果需要建立新的连接，就new一个ClientLink，同时记录连接的目标，然后加入列表是，设置client可用
	void MfCloseLink(std::string Linkname);							// 关闭某个连接
	bool MfSendMsg(std::string name, int MsgId, const char* data, int len);
	const char* MfGetRecvBufferP(std::string name);					// 返回接收缓冲区的指针，可以直接读这里的数据
	bool MfHasMsg(std::string name);								// 判断缓冲区是否有数据
	void MfPopFrontMsg(std::string name);							// 缓冲区数据按包弹出
	bool MfLinkIsSurvive(std::string name);							// 某个服务是否活着
private:
	void MfSendThread();											// 发送线程，循环调用send，收发线程根据是否可用标志确定行为
	void MfRecvThread();											// 接收线程，循环调用recv，收发线程根据是否可用标志确定行为
public:
	bool RegMsg(std::string LinkName, int MsgId, MsgFunType fun);
};

CClientLinkManage::CClientLinkManage(int HeartSendInterval) :
	MdBarrier(nullptr),
	MdHeartSendInterval(HeartSendInterval),
	MdDefautHeartPacket(nullptr),
	MdHeartTime(nullptr)
{
	MdBarrier = new Barrier;
	MdDefautHeartPacket = new CNetMsgHead;
	MdHeartTime = new CTimer;
}

CClientLinkManage::~CClientLinkManage()
{
	{
		std::unique_lock<std::shared_mutex> lk(MdClientLinkListMtx);
		for (auto it = MdClientLinkList.begin(); it != MdClientLinkList.end();)
		{
			it->second->MfClose();
			MdClientLinkList.erase(it++);
		}
	}

	if (nullptr != MdBarrier)
		delete MdBarrier;
	MdBarrier = nullptr;

	if (nullptr != MdDefautHeartPacket)
		delete MdDefautHeartPacket;
	MdDefautHeartPacket = nullptr;

	if (nullptr != MdHeartTime)
		delete MdHeartTime;
	MdHeartTime = nullptr;
}

void CClientLinkManage::MfStart()
{
	MdBarrier->MfInit(3);
	MdThreadPool.MfStart(2);
	// 启动收发线程,需要做的是在启动收发线程前不应该建立连接
	MdThreadPool.MfEnqueue(std::bind(&CClientLinkManage::MfSendThread, this));
	MdThreadPool.MfEnqueue(std::bind(&CClientLinkManage::MfRecvThread, this));
	MdBarrier->MfWait();
	MdIsStart = 1;
}

int CClientLinkManage::MfCreateAddLink(std::string Linkname, const char* ip, unsigned short port)
{
	if (!MdIsStart.load())
	{
		return SOCKET_ERROR;
	}

	{
		std::shared_lock<std::shared_mutex> lk(MdClientLinkListMtx);
		if (MdClientLinkList.find(Linkname) != MdClientLinkList.end())
		{
			return SOCKET_ERROR;
		}
	}

	CClientLink* temp = new	CClientLink(Linkname);
	int ret = temp->MfConnect(ip, port);
	if (SOCKET_ERROR != ret)	// 成功连接后就加入正式队列
	{
		std::unique_lock<std::shared_mutex> lk(MdClientLinkListMtx);
		MdClientLinkList.insert(std::pair<std::string, CClientLink*>(Linkname, temp));
		return ret;
	}
	delete temp;
	return SOCKET_ERROR;
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

bool CClientLinkManage::MfHasMsg(std::string name)
{
	auto it = MdClientLinkList.find(name);
	if (it == MdClientLinkList.end())
		return false;
	return it->second->MfHasMsg();
}

void CClientLinkManage::MfPopFrontMsg(std::string name)
{
	auto it = MdClientLinkList.find(name);
	if (it == MdClientLinkList.end())
		return;
	return it->second->MfPopFrontMsg();
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

	MdBarrier->MfWait();

	// 主循环
	while (!MdThreadPool.MfIsStop())
	{
		// 为每个连接发送心跳包,这里是把心跳包加入第二缓冲区，之后一起由循环整个一起发送
		if (MdHeartTime->getElapsedSecond() > MdHeartSendInterval)
		{
			std::shared_lock<std::shared_mutex> lk(MdClientLinkListMtx);
			for (auto it = MdClientLinkList.begin(); it != MdClientLinkList.end(); ++it)
				it->second->MfDataToBuffer((const char*)MdDefautHeartPacket, sizeof(CNetMsgHead));
			MdHeartTime->update();
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

	MdBarrier->MfWait();

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

				while (it->second->MfHasMsg())
				{
					if (-1 == ((CNetMsgHead*)(it->second->MfGetRecvBufferP()))->MdCmd)	// 当该包的该字段为-1时，代表心跳
						it->second->GetScoketObj()->MfHeartBeatUpDate();
					else
						it->second->MfVNetMsgDisposeFun(it->second->MfGetSocket(), it->second->GetScoketObj(), (CNetMsgHead*)it->second->MfGetRecvBufferP(), threadid);
					it->second->MfPopFrontMsg();
				}
				++it;
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

bool CClientLinkManage::RegMsg(std::string LinkName, int MsgId, MsgFunType fun)
{
	auto it = MdClientLinkList.find(LinkName);
	if (it == MdClientLinkList.end())
		return false;
	return it->second->RegMsg(MsgId, fun);
}

class CServiceNoBlock
{
protected:
	SOCKET								MdListenSock;				// 监听套接字
	int									MdServiceMaxPeoples;		// 该服务的上限人数
	int									MdDisposeThreadNums;		// 消息处理线程数
	int									MdHeartBeatTime;			// 心跳时限，该时限内未收到消息默认断开，单位秒
	CTimer* MdHeartBeatTestInterval;	// 心跳间隔检测用到的计时器
	CObjectPool<CSocketObj>* Md_CSocketObj_POOL;			// 客户端对象的对象池
	std::map<SOCKET, CSocketObj*>* MdPClientJoinList;			// 非正式客户端缓冲列表，等待加入正式列表，同正式客户列表一样，一个线程对应一个加入列表
	std::mutex* MdPClientJoinListMtx;		// 非正式客户端列表的锁
	std::map<SOCKET, CSocketObj*>* MdPClientFormalList;		// 正式的客户端列表，一个线程对应一个map[],存储当前线程的服务对象,map[threadid]找到对应map，map[threadid][socket]找出socket对应的数据
	std::shared_mutex* MdPClientFormalListMtx;		// 为一MdPEachDisoposeThreadOfServiceObj[]添加sock时，应MdEachThreadOfMtx[].lock
	std::map<SOCKET, CSocketObj*>* MdClientLeaveList;			// 等待从正式列表中移除的缓冲列表
	std::mutex* MdClientLeaveListMtx;		// 移除列表的锁
	CThreadPool* MdThreadPool;
	std::map<int, MsgFunType> MsgDealFuncMap;
protected:			// 用来在服务启动时，等待其他所有线程启动后，再启动Accept线程
	Barrier* MdBarrier1;
protected:			// 这一组变量，用来在服务结束时，按accept recv dispose send的顺序来结束线程以保证不出错
	Barrier* MdBarrier2;		// accept线程		和	recv线程			的同步变量		！！！！！在epoll中未被使用！！！！！
	Barrier* MdBarrier3;		// recv线程			和	所有dispos线程		的同步变量
	Barrier* MdBarrier4;		// send线程			和	dispose线程			的同步和前面不同，用屏障的概念等待多个线程来继续执行
public:
	CServiceNoBlock(int HeartBeatTime = 300, int ServiceMaxPeoples = 1000, int DisposeThreadNums = 1);
	virtual ~CServiceNoBlock();
	void Mf_NoBlock_Start(const char* ip, unsigned short port);		// 启动收发处理线程的非阻塞版本
protected:
	bool Mf_Init_ListenSock(const char* ip, unsigned short port);	// 初始化套接字
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
			return;

		Fun->second(cli, ((char*)msg) + sizeof(CNetMsgHead), msg->MdLen - sizeof(CNetMsgHead));
	}
};

// --------------------------------------------------------分割线--------------------------------------------------------
// --------------------------------------------------------分割线--------------------------------------------------------
// --------------------------------------------------------分割线--------------------------------------------------------
// --------------------------------------------------------分割线--------------------------------------------------------

#ifndef WIN32

class CServiceEpoll :public CServiceNoBlock
{
private:
	std::vector<SOCKET>			MdEpoll_In_Fd;		// epoll句柄
	std::vector<epoll_event*>	MdEpoll_In_Event;	// 接收线程用到的结构集合
	int							MdThreadAvgPeoples;	// 每个线程的平均人数
public:
	CServiceEpoll(int HeartBeatTime = 300, int ServiceMaxPeoples = 1000, int DisposeThreadNums = 1);
	virtual ~CServiceEpoll();
	bool Mf_Epoll_Start(const char* ip, unsigned short port);
private:
	void Mf_Epoll_AcceptThread();							// 等待客户端连接的线程
	void Mf_Epoll_RecvAndDisposeThread(int SeqNumber);		// 处理线程
	void Mf_Epoll_SendThread();								// 发线程
	void Mf_Epoll_ClientJoin(std::thread::id threadid, int SeqNumber);	// 客户端加入正式列表
	void Mf_Epoll_ClientLeave(std::thread::id threadid, int SeqNumber);	// 客户端移除正式列表
};

#endif // !WIN32

CServiceNoBlock::CServiceNoBlock(int HeartBeatTime, int ServiceMaxPeoples, int DisposeThreadNums) :
	MdServiceMaxPeoples(ServiceMaxPeoples),
	MdDisposeThreadNums(DisposeThreadNums),
	MdHeartBeatTime(HeartBeatTime),
	MdHeartBeatTestInterval(nullptr),
	Md_CSocketObj_POOL(nullptr),
	MdPClientJoinList(nullptr),
	MdPClientJoinListMtx(nullptr),
	MdPClientFormalList(nullptr),
	MdPClientFormalListMtx(nullptr),
	MdClientLeaveList(nullptr),
	MdClientLeaveListMtx(nullptr),
	MdBarrier1(nullptr),
	MdBarrier2(nullptr),
	MdBarrier3(nullptr),
	MdBarrier4(nullptr),
	MdThreadPool(nullptr)
{
	MdHeartBeatTestInterval = new CTimer;
	Md_CSocketObj_POOL = new CObjectPool<CSocketObj>(MdServiceMaxPeoples);
	MdPClientFormalList = new std::map<SOCKET, CSocketObj*>[MdDisposeThreadNums];
	MdPClientFormalListMtx = new std::shared_mutex[MdDisposeThreadNums];
	MdPClientJoinList = new std::map<SOCKET, CSocketObj*>[MdDisposeThreadNums];
	MdPClientJoinListMtx = new std::mutex[MdDisposeThreadNums];
	MdClientLeaveList = new std::map<SOCKET, CSocketObj*>[MdDisposeThreadNums];
	MdClientLeaveListMtx = new std::mutex[MdDisposeThreadNums];
	MdBarrier1 = new Barrier;
	MdBarrier2 = new Barrier;
	MdBarrier3 = new Barrier;
	MdBarrier4 = new Barrier;
	MdThreadPool = new CThreadPool;
}

CServiceNoBlock::~CServiceNoBlock()
{
	if (MdThreadPool)
		delete MdThreadPool;
	MdThreadPool = nullptr;

	if (MdHeartBeatTestInterval)
		delete MdHeartBeatTestInterval;
	MdHeartBeatTestInterval = nullptr;

	if (Md_CSocketObj_POOL)
		delete Md_CSocketObj_POOL;
	Md_CSocketObj_POOL = nullptr;

	if (MdPClientFormalList)
		delete[] MdPClientFormalList;
	MdPClientFormalList = nullptr;

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

	if (MdBarrier1)
		delete MdBarrier1;
	MdBarrier1 = nullptr;

	if (MdBarrier2)
		delete MdBarrier2;
	MdBarrier2 = nullptr;

	if (MdBarrier3)
		delete MdBarrier3;
	MdBarrier3 = nullptr;

	if (MdBarrier4)
		delete MdBarrier4;
	MdBarrier4 = nullptr;
}

void CServiceNoBlock::Mf_NoBlock_Start(const char* ip, unsigned short port)
{
	Mf_Init_ListenSock(ip, port);

	// 处理线程同步
	MdBarrier1->MfInit(MdDisposeThreadNums + 2 + 1);	// 处理线程数量 + send和recv线程 + recv线程本身
	MdBarrier2->MfInit(2);								// accept + recv两条线程
	MdBarrier3->MfInit(MdDisposeThreadNums + 1);		// 处理线程数量 + recv线程
	MdBarrier4->MfInit(MdDisposeThreadNums + 1);		// 处理线程数量 + send线程

	// 启动各个线程
	MdThreadPool->MfStart(1 + MdDisposeThreadNums + 1 + 1);
	MdThreadPool->MfEnqueue(std::bind(&CServiceNoBlock::Mf_NoBlock_SendThread, this));			// 启动发送线程
	for (int i = 0; i < MdDisposeThreadNums; ++i)
		MdThreadPool->MfEnqueue(std::bind(&CServiceNoBlock::Mf_NoBlock_DisposeThread, this, i));	// 启动多条处理线程线程
	MdThreadPool->MfEnqueue(std::bind(&CServiceNoBlock::Mf_NoBlock_RecvThread, this));			// 启动接收线程
	MdThreadPool->MfEnqueue(std::bind(&CServiceNoBlock::Mf_NoBlock_AcceptThread, this));			// 启动等待连接线程
}

bool CServiceNoBlock::Mf_Init_ListenSock(const char* ip, unsigned short port)
{
	std::thread::id threadid = std::this_thread::get_id();

	// 初始化监听套接字
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

	MdListenSock = socket(AF_INET, SOCK_STREAM, 0);
	if (SOCKET_ERROR == MdListenSock)
		return false;
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
	MdBarrier1->MfWait();

	// 主循环，每次循环接收一个连接
	while (!MdThreadPool->MfIsStop())
	{
		currPeoples = 0;
		for (int i = 0; i < MdDisposeThreadNums; ++i)	// 计算当前已连接人数
			currPeoples += (int)MdPClientFormalList[i].size();
		if (currPeoples > MdServiceMaxPeoples)	// 大于上限服务人数，就不accpet，等待然后开始下一轮循环
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
			minPeoples = INT32_MAX;
			for (int i = 0; i < MdDisposeThreadNums; ++i)	// 找出人数最少的
			{
				if (minPeoples > (int)MdPClientFormalList[i].size())
				{
					minPeoples = (int)MdPClientFormalList[i].size();
					minId = i;
				}
			}
			CSocketObj* TempSocketObj = Md_CSocketObj_POOL->MfApplyObject(sock);
			TempSocketObj->MfSetPeerAddr(&addr);
			TempSocketObj->MfSetThreadIndex(minId);
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

	MdBarrier2->MfWait();
}

void CServiceNoBlock::Mf_NoBlock_RecvThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	MdBarrier1->MfWait();

	int ret = 0;

	// 主循环
	while (!MdThreadPool->MfIsStop())
	{
		for (int i = 0; i < MdDisposeThreadNums; ++i)
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
	MdBarrier2->MfWait();

	// 然后对所有套接字最后一次接收
	for (int i = 0; i < MdDisposeThreadNums; ++i)
	{
		std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);
		for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
			it->second->MfRecv();
	}


	// 接下来通知所有dispose线程
	MdBarrier3->MfWait();
}

void CServiceNoBlock::Mf_NoBlock_DisposeThread(int SeqNumber)
{
	std::thread::id threadid = std::this_thread::get_id();
	CTimer time;

	MdBarrier1->MfWait();

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
				while (it.second->MfHasMsg())
				{
					if (-1 == ((CNetMsgHead*)it.second->MfGetRecvBufP())->MdCmd)	// 当该包的该字段为-1时，代表心跳
						it.second->MfHeartBeatUpDate();		// 更新心跳计时
					else
						MfVNetMsgDisposeFun(it.first, it.second, (CNetMsgHead*)it.second->MfGetRecvBufP(), threadid);
					it.second->MfPopFrontMsg();
				}
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// 主循环结束后，所有处理线程都等待recv线程发来的通知
	MdBarrier3->MfWait();

	// 对所有套接字进行最后一次处理
	for (auto it : MdPClientFormalList[SeqNumber])
	{
		while (it.second->MfHasMsg())
		{
			MfVNetMsgDisposeFun(it.first, it.second, (CNetMsgHead*)it.second->MfGetRecvBufP(), threadid);
			it.second->MfPopFrontMsg();
		}
	}

	MdBarrier4->MfWait();
}

void CServiceNoBlock::Mf_NoBlock_SendThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	MdBarrier1->MfWait();

	int ret = 0;

	// 主循环
	while (!MdThreadPool->MfIsStop())
	{
		for (int i = 0; i < MdDisposeThreadNums; ++i)
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
	MdBarrier4->MfWait();

	// 发送所有数据
	for (int i = 0; i < MdDisposeThreadNums; ++i)
	{
		std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);
		for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
			it->second->MfSend();
	}

	// 关闭所有套接字
	for (int i = 0; i < MdDisposeThreadNums; ++i)
	{
		for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
		{
			it->second->MfClose();
			Md_CSocketObj_POOL->MfReturnObject(it->second);
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
			MdPClientFormalList[SeqNumber].insert(std::pair<SOCKET, CSocketObj*>(it->first, it->second));
		}
		MdPClientJoinList[SeqNumber].clear();
	}
}

void CServiceNoBlock::Mf_NoBlock_ClientLeave(std::thread::id threadid, int SeqNumber)
{
	static const int HeartIntervalTime = MdHeartBeatTime / 3;		// 心跳检测间隔时限

	// 本函数中的两个也都使用尝试锁，因为这里不是重要的地方，也不是需要高效执行的地方
	std::unique_lock<std::mutex> lk(MdClientLeaveListMtx[SeqNumber], std::defer_lock);
	std::unique_lock<std::shared_mutex> WriteLock(MdPClientFormalListMtx[SeqNumber], std::defer_lock);
	if (lk.try_lock() && WriteLock.try_lock())
	{
		// 第一个循环每隔 心跳超时时间的三分之一 检测一次心跳是否超时
		if (HeartIntervalTime < MdHeartBeatTestInterval->getElapsedSecond())
		{
			// 遍历当前列表的客户端心跳计时器，超时就放入待离开列表
			for (auto it : MdPClientFormalList[SeqNumber])
			{
				if (it.second->MfHeartIsTimeOut(MdHeartBeatTime))
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
				MdPClientFormalList[SeqNumber].erase(it->first);
				it->second->MfClose();
				Md_CSocketObj_POOL->MfReturnObject(it->second);
			}
			MdClientLeaveList[SeqNumber].clear();
		}
	}
}

// --------------------------------------------------------分割线--------------------------------------------------------
// --------------------------------------------------------分割线--------------------------------------------------------
// --------------------------------------------------------分割线--------------------------------------------------------
// --------------------------------------------------------分割线--------------------------------------------------------

#ifndef WIN32
CServiceEpoll::CServiceEpoll(int HeartBeatTime, int ServiceMaxPeoples, int DisposeThreadNums) :
	CServiceNoBlock(HeartBeatTime, ServiceMaxPeoples, DisposeThreadNums)
{
	MdThreadAvgPeoples = (MdServiceMaxPeoples / MdDisposeThreadNums) + 100;
	for (int i = 0; i < MdDisposeThreadNums; ++i)
	{
		MdEpoll_In_Event.push_back(new epoll_event[MdThreadAvgPeoples]);
	}
}

CServiceEpoll::~CServiceEpoll()
{
	for (auto it : MdEpoll_In_Event)
		delete[] it;
}

bool CServiceEpoll::Mf_Epoll_Start(const char* ip, unsigned short port)
{
	for (int i = 0; i < MdDisposeThreadNums; ++i)		// 为各个处理线程建立epoll的描述符
	{
		MdEpoll_In_Fd.push_back(epoll_create(MdThreadAvgPeoples));
	}

	for (int i = 0; i < MdDisposeThreadNums; ++i)		// 检查各个描述符是否出错
	{
		if (-1 == MdEpoll_In_Fd[i])
		{

		}
	}

	if (!Mf_Init_ListenSock(ip, port))
		return false;

	// 处理线程同步
	MdBarrier1->MfInit(MdDisposeThreadNums + 1 + 1);	// 处理线程数量 + send和recv线程 + recv线程本身
	MdBarrier2->MfInit(2);								// 在epoll中未被使用
	MdBarrier3->MfInit(MdDisposeThreadNums + 1);		// accept + 处理线程数量
	MdBarrier4->MfInit(MdDisposeThreadNums + 1);		// 处理线程数量 + send线程

	MdThreadPool->MfStart(1 + MdDisposeThreadNums + 1);
	MdThreadPool->MfEnqueue(std::bind(&CServiceEpoll::Mf_Epoll_SendThread, this));					// 启动发送线程
	for (int i = 0; i < MdDisposeThreadNums; ++i)
		MdThreadPool->MfEnqueue(std::bind(&CServiceEpoll::Mf_Epoll_RecvAndDisposeThread, this, i));	// 启动多条处理线程,！！！！收线程和处理线程合并了！！！！
	MdThreadPool->MfEnqueue(std::bind(&CServiceEpoll::Mf_Epoll_AcceptThread, this));		// 启动等待连接线程			
	return true;
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
	MdBarrier1->MfWait();

	// 主循环，每次循环接收一个连接
	while (!MdThreadPool->MfIsStop())
	{
		currPeoples = 0;
		for (int i = 0; i < MdDisposeThreadNums; ++i)	// 计算当前已连接人数
			currPeoples += (int)MdPClientFormalList[i].size();
		if (currPeoples > MdServiceMaxPeoples)	// 大于上限服务人数，就不accpet，等待然后开始下一轮循环
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
			minPeoples = INT32_MAX;
			for (int i = 0; i < MdDisposeThreadNums; ++i)			// 找出人数最少的
			{
				if (minPeoples > (int)MdPClientFormalList[i].size())
				{
					minPeoples = (int)MdPClientFormalList[i].size();
					minId = i;
				}
			}
			CSocketObj* TempSocketObj = Md_CSocketObj_POOL->MfApplyObject(sock);
			TempSocketObj->MfSetPeerAddr(&addr);
			TempSocketObj->MfSetThreadIndex(minId);
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
	MdBarrier3->MfWait();
}

void CServiceEpoll::Mf_Epoll_RecvAndDisposeThread(int SeqNumber)
{
	std::thread::id threadid = std::this_thread::get_id();
	CTimer time;

	MdBarrier1->MfWait();

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
				while (tmp_obj->MfHasMsg())
				{
					if (-1 == ((CNetMsgHead*)tmp_obj->MfGetRecvBufP())->MdCmd)	// 当该包的该字段为-1时，代表心跳包
						tmp_obj->MfHeartBeatUpDate();		// 更新心跳计时
					else
						MfVNetMsgDisposeFun(tmp_fd, tmp_obj, (CNetMsgHead*)tmp_obj->MfGetRecvBufP(), threadid);
					tmp_obj->MfPopFrontMsg();
				}
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// 主循环结束后，所有处理线程都等待recv线程发来的通知
	MdBarrier3->MfWait();

	// 对所有套接字进行最后一次处理
	std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[SeqNumber]);
	Epoll_N_Fds = epoll_wait(MdEpoll_In_Fd[SeqNumber], MdEpoll_In_Event[SeqNumber], MdThreadAvgPeoples, 0);
	for (int j = 0; j < Epoll_N_Fds; ++j)
	{
		tmp_fd = MdEpoll_In_Event[SeqNumber][j].data.fd;
		tmp_obj = MdPClientFormalList[SeqNumber][tmp_fd];
		ret = tmp_obj->MfRecv();
		while (tmp_obj->MfHasMsg())
		{
			MfVNetMsgDisposeFun(tmp_fd, tmp_obj, (CNetMsgHead*)tmp_obj->MfGetRecvBufP(), threadid);
			tmp_obj->MfPopFrontMsg();
		}
	}

	MdBarrier4->MfWait();
}

void CServiceEpoll::Mf_Epoll_SendThread()
{
	std::thread::id threadid = std::this_thread::get_id();

	MdBarrier1->MfWait();

	int ret = 0;

	// 主循环
	while (!MdThreadPool->MfIsStop())
	{
		for (int i = 0; i < MdDisposeThreadNums; ++i)
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
	MdBarrier4->MfWait();

	// 发送所有数据
	for (int i = 0; i < MdDisposeThreadNums; ++i)
	{
		std::shared_lock<std::shared_mutex> ReadLock(MdPClientFormalListMtx[i]);
		for (auto it : MdPClientFormalList[i])
		{
			it.second->MfSend();
		}
	}

	for (int i = 0; i < MdDisposeThreadNums; ++i)
	{
		for (auto it = MdPClientFormalList[i].begin(); it != MdPClientFormalList[i].end(); ++it)
		{
			it->second->MfClose();
			Md_CSocketObj_POOL->MfReturnObject(it->second);
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
			MdPClientFormalList[SeqNumber].insert(std::pair<SOCKET, CSocketObj*>(it->first, it->second));
			EvIn.data.fd = it->first;
			epoll_ctl(MdEpoll_In_Fd[SeqNumber], EPOLL_CTL_ADD, it->first, &EvIn);		// 设置套接字到收线程的Epoll
		}
		MdPClientJoinList[SeqNumber].clear();
	}
}

void CServiceEpoll::Mf_Epoll_ClientLeave(std::thread::id threadid, int SeqNumber)
{
	static const int HeartIntervalTime = MdHeartBeatTime / 3;		// 心跳检测间隔时限

	// 本函数中的两个也都使用尝试锁，因为这里不是重要的地方，也不是需要高效执行的地方
	std::unique_lock<std::mutex> lk(MdClientLeaveListMtx[SeqNumber], std::defer_lock);
	std::unique_lock<std::shared_mutex> WriteLock(MdPClientFormalListMtx[SeqNumber], std::defer_lock);
	if (lk.try_lock() && WriteLock.try_lock())
	{
		// 第一个循环每隔 心跳超时时间的三分之一 检测一次心跳是否超时
		if (HeartIntervalTime < MdHeartBeatTestInterval->getElapsedSecond())
		{
			// 遍历当前列表的客户端心跳计时器，超时就放入待离开列表
			for (auto it : MdPClientFormalList[SeqNumber])
			{
				if (it.second->MfHeartIsTimeOut(MdHeartBeatTime))
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
				it->second->MfClose();
				epoll_ctl(MdEpoll_In_Fd[SeqNumber], EPOLL_CTL_DEL, it->first, nullptr);
				MdPClientFormalList[SeqNumber].erase(it->first);
				Md_CSocketObj_POOL->MfReturnObject(it->second);
			}
			MdClientLeaveList[SeqNumber].clear();
		}
	}
}
#endif