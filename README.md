开发说明
===
本项目最初来源于HustLion的fork：
>接续HustMoon开发的MentoHUST，继续更新。
>搬运完毕，即将开始各种修改。记下原始的地址以示纪念： http://mentohust.googlecode.com/
>
>开发的主要目标是使得OpenWRT下的MentoHUST更加友好，对其他平台的适配暂无计划。

V4认证算法来源于hyrathb：
>完全没怎么看原来的代码，瞎改的。
>加入了V4支持。具体算法看checkV4.c
>
>所有hash都是从算法在rhash和ampheck借来魔改的……。

代理认证由updateing实现。

使用方法
===

####安装MentoHUST
建议Ubuntu用户使用Deb包安装，Fedora用户使用RPM包安装

####如果确定xrgsu可用
打开终端输入`sudo mentohust`运行即可

####如果不确定xrgsu的可用性
请切换到***32位版***Windows锐捷所在目录，然后输入以下命令：
```
sudo mkdir /etc/mentohust
sudo cp ./8021x.exe  /etc/mentohust
sudo cp ./W32N55.dll /etc/mentohust
```
然后打开终端输入`sudo mentohust`运行。如果认证失败，再切换到Windows版锐捷所在目录，输入以下命令：
```
sudo cp ./SuConfig.dat /etc/mentohust
```
然后打开终端输入`sudo mentohust`运行即可。
如果按以上步骤操作后还是认证失败，请下载MentoHUSTTool，在Windows下抓包并保存为data.mpf，
然后回到Linux，切换到data.mpf所在目录，输入以下命令：
```
sudo cp ./data.mpf /etc/mentohust
```
然后打开终端输入
```
sudo mentohust -f/etc/mentohust/data.mpf -w
```
运行即可。以后也只需输入`sudo mentohust`。

####您也可以按下面的方法操作
1. 静态IP用户请事先设置好IP；
2. 打开终端，输入`sudo mentohust`，回车；
3. 输入相应信息，如果认证成功，跳到第8步；如果提示“不允许使用的客户端类型”，按Ctrl+C结束认证；
4. 打开终端，输入sudo mentohust -w -f'锐捷目录下任意文件路径'，回车；
5. 如果认证成功，跳到第8步；如果提示“客户端完整性被破坏”，按Ctrl+C结束认证；
6. 将锐捷安装目录下的SuConfig.dat重命名为其他名字；
7. 打开终端，输入`sudo mentohust`，回车；
8. 如果是动态IP且不是Linux，打开相应设置去更新IP。
9. 以后认证只需打开终端，输入`sudo mentohust`，回车。
10. 要修改某些参数请输入`mentohust -h`查看帮助信息并据此修改，例如修改密码sudo mentohust -pNewPassword -w，要临时修改则不加-w参数。

####如何退出
不以后台模式运行MentoHUST时，按Ctrl+C即可退出；后台运行时使用`sudo mentohust -k`退出认证。

####查看命令行选项说明
```
mentohust -h
```
更详细的帮助信息请参考：http://wiki.ubuntu.org.cn/锐捷、赛尔认证MentoHUST

####修改认证参数
请根据帮助信息操作，例如修改用户名和密码并保存：
```
sudo mentohust -uUsername -pPassword -w
```
不加-w参数则表明修改只对本次认证生效，例如***临时***修改用户名和密码：
```
sudo mentohust -uUsername -pPassword
```

####如果提示缺少libpcap.so.0.x而在/usr/lib/目录下已存在一个libpcap.so.0.x.y
```
sudo ln -s libpcap.so.0.x.y /usr/lib/libpcap.so.0.x
```
否则请安装libpcap。

####代理认证
在代理认证模式下，MentoHUST不会自行完成整个认证流程，而是充当802.1x路由器，由局域网内其他设备协助完成认证。

在命令行中指定-z为连接局域网的网卡，代理模式即会开启，无需为MentoHUST指定用户名和密码。

代理模式下，MentoHUST将会按照以下流程工作：

1. 从命令行读取局域网网卡名（-z）、上游接口名（-n）、需求成功次数（-j）等。
2. 将局域网和连接上游的网卡设置为混杂模式。开始在局域网内监听一切802.1x认证数据包（protocol字段为0x888E）。
3. 当收到客户端发来的EAPOL-Start包时，保存客户端MAC地址，并用自己的算法构造出一个新的EAPOL-Start包，向上游发送。
4. 当上游服务器发来EAP-Request-Identity时，保存服务器的MAC地址，将此包的目标MAC地址由连接上游网卡的MAC地址改为客户端MAC地址，向局域网发送。
5. 当客户端发来EAP-Response-Identity时，将此包的源MAC地址由客户端MAC地址改为上游服务器的MAC地址，向上游发送。
6. 对于接下来的MD5 Challenge重复4和5.
7. 对于最后的EAP-Success或Failure重复4. 若为Success，且已收到的Success包个数大于等于-j指定的值，则停止对局域网的监听。否则继续监听。

当认证成功后，上游服务器发来EAP-Request-Identity、MD5 Challenge或Failure时，MentoHUST将重新开始监听局域网，并把这些包修改目标MAC地址后转发到局域网，客户端可自行处理。

**注意**：由于需要由MentoHUST来构造EAPOL-Start包，因此DHCP类型、组播地址需要正确设定。

代理认证相关设置暂不支持写入配置文件，仅可通过命令行使用。

其他事项
===
####开发者资源
本软件采用The GNU Build System

####权责声明
1、本程序所有涉及锐捷赛尔认证的功能均是来自前辈公开代码及抓包分析。
2、本程序于个人仅供学习，于他人仅供方便认证，不得使用本程序有意妨害锐捷赛尔认证机制及相关方利益。
3、一切使用后果由用户自己承担。
4、本程序不提供任何服务及保障，编写及维护纯属个人爱好，随时可能被终止。
5、使用本程序者，即表示同意该声明。谢谢合作。

源码可在项目主页获取：http://mentohust.googlecode.com/
联系作者：在 http://mentohust.googlecode.com/ 留言，或Email： mentohust@ehust.co.cc
