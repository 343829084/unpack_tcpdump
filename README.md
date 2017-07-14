<<<<<<< HEAD
需要安装 dpkt 及pandas二个库,后一个是画图用的，可以不装
 https://github.com/kbandla/dpkt.git
 安装命令：python setup.py -j 4 build install --prefix $HOME/.local

 tcp协议，它的data最大长度为1448字节，当消息很大时，会进行分片到多个tcp包中，在解包时，需要根据ip.src,sport ,ip.dst dport 及tcp.seq确定分片次序
 udp
=======
需要安装 dpkt 及pandas二个库注意这里解包是解的tcp包，而不是udp包，需要根据tcp/udp消息头来进行解包，对于udp组播的头，也需要注意，它与udp的头不一样。
>>>>>>> e49833edfa2c638515c3b218052b3f01a0400ec8
