package lanPortScanner445.IP;

import java.net.InetAddress;
import java.net.Socket;

public class Child implements Runnable{
	Thread me;
	InetAddress address;
	int port;
	IP main;
	public Child(InetAddress ad, int p,IP m) {
		address = ad;
		port = p;
		main = m;
		start();

	}
	void start() {
		if(me==null) {
			me=new Thread(this);
			me.start();

		}
	}
	void stop() {
		me = null;

	}
	public void run() {
		// TODO 自動生成されたメソッド・スタブ
		Socket sock = null ;
		int countPorts = 0 ;
		int timeout_msec = 2000;
		try {
			 sock = new Socket( address, port);
			 System.out.println(address);
		}
		catch(Exception e){
			System.out.println("ipaddr="+address+":"+port+" "+e);
			me = null;
			return;
		}
		countPorts++ ;	// ひらいているポートとしてカウント
		main.setOpen(address,port);
		try {
		sock.close() ;	// クローズ
		}
		catch(Exception e) {
			System.out.println("2"+e);
		}
		me = null;
	}
}
