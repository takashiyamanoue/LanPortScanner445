package lanPortScanner445.IP;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.LinkLayerAddress;
import java.net.Socket;
//import java.net.*;
//import java.util.*;
//import java.net.ServerSocket;

public class IP{
	public static void main(String args[]) {
        try {
            //IPアドレスの取得
            InetAddress ia = InetAddress.getLocalHost();
            String ip = ia.getHostAddress();
            //画面表示
            System.out.println("IPアドレス：" + ip);
            }
        catch (Exception e) {
            e.printStackTrace();
        }
        IP ip=new IP();
        System.out.println("\n取得できるすべてのIPアドレスをすべて表示");
		}



	public IP() {
		networkInterfaces=new Vector();
		try {
		setNetworkInterfaces();
		}
		catch(Exception e) {
		}
		//printIPAddress();
	}

	public PcapAddress getIpV4Address(PcapNetworkInterface iface) {
//      List<PcapAddr> alist=iface.getAddresses();
		List<PcapAddress> alist=iface.getAddresses();
//      PcapAddr addr=null;
	    PcapAddress addr=null;
//      PcapSockAddr sockaddr=null;
//		InetSocketAddress sockaddr=null;
      System.out.println("address-number="+alist.size());
      if(alist.size()>=1)
      	for(int j=0;j<alist.size();j++){
              addr=alist.get(j);
//              sockaddr=addr.getAddr();
//              InetAddress iaddr=addr.getAddress();
              Class cx=addr.getClass();
              if(cx.getName()=="org.pcap4j.core.PcapIpV4Address") {
              	return addr;
              }
              /*
              if(sockaddr.getFamily()==PcapSockAddr.AF_INET){
              	return addr;
              }
              */
      	}
      return null;
	}
	Vector <PcapNetworkInterface> networkInterfaces;
	int lanSideInterface;

    public void setNetworkInterfaces()throws IOException {
        networkInterfaces.removeAllElements();//vecterからすべての要素を削除し、サイズを０に設定する
//		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
        List<PcapNetworkInterface> alldevs =new ArrayList<PcapNetworkInterface>();
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		/*
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}
		*/
		try {
		alldevs=Pcaps.findAllDevs();
		}
		catch(Exception e) {

		}
		if(alldevs==null) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
				    .toString());
				return;
		}

		/***************************************************************************
		 * Second iterate through all the interface and get the HW addresses
		 **************************************************************************/
		int row=0;
//		for (final PcapIf i : alldevs) {
		for (final PcapNetworkInterface i:alldevs) {
//			final byte[] mac = i.getHardwareAddress();

			ArrayList<LinkLayerAddress> macs = i.getLinkLayerAddresses();
//			if (mac == null) {
			if (macs ==null) {
			 continue; // Interface doesn't have a hardware address
			}
//			for(final LinkLayerAddress mac:macs) {
//               if(mac==null) continue;
               String description =
                  (i.getDescription() != null) ? i.getDescription()
                      : "No description available";
             /*
            List<PcapAddr> alist=i.getAddresses();
            PcapAddr addr=null;
            if(alist.size()>=1)
               addr=alist.get(0);
            */
//               PcapAddr addr=this.getIpV4Address(i);
               PcapAddress addr=this.getIpV4Address(i);
//               PcapSockAddr psockaddr=null;
               InetAddress psockaddr=null;
//               PcapSockAddr pmaskaddr=null;
               InetAddress pmaskaddr=null;
               if(addr!=null){
//            	  psockaddr=addr.getAddr();
            	  psockaddr=addr.getAddress();
//                  String addrx=FormatUtils.ip(psockaddr.getData());
            	  String addrx=psockaddr.getHostAddress();
            	  System.out.println("addrx ="+addrx);
                  //interfaceTable.setValueAt(addrx,row, 5);
                  pmaskaddr=addr.getNetmask();
                  System.out.println("pmaskaddrx ="+pmaskaddr);
//                  String maskx=FormatUtils.ip(pmaskaddr.getData());
                  String maskx=pmaskaddr.getHostAddress();
                  System.out.println("maskx ="+maskx);
                  //interfaceTable.setValueAt(maskx,row, 6);
                  hostlist(addr);
               }
			   System.out.printf("%s=%s\n", i.getName(), (macs.get(0)).toString());
			  // interfaceTable.setValueAt(i.getName(), row, 2);
			  //interfaceTable.setValueAt((macs.get(0)).toString(),row,4);
			  // interfaceTable.setValueAt(description, row, 3);
			  // interfaceTable.setValueAt("",row,0);
			   networkInterfaces.addElement(i);
//			}
			row++;
		}
      //  interfaceTable.setValueAt("!", 0, 0);
        this.lanSideInterface=0;

	/**
	 * @param hardwareAddress
	 * @return
	 */
   }

	/*public static void printIPAddress()  {
		try {
		Enumeration <NetworkInterface> netSet;//集合内の列挙操作
		netSet = NetworkInterface.getNetworkInterfaces();
		while(netSet.hasMoreElements()){    //interface走査
			NetworkInterface nInterface = (NetworkInterface) netSet.nextElement();
			List<InterfaceAddress>list = nInterface.getInterfaceAddresses();
			if( list.size() == 0 ) continue;
			System.out.println(nInterface .getName() );//net識別名
			for (InterfaceAddress interfaceAdr : list){
				InetAddress inet = interfaceAdr.getAddress();
		//		 IP.print(inet);//IPアドレスの表示
				System.out.println("x="+inet.getHostAddress());

				}
			}
		}
		catch(
			Exception e) {

		}

	}*/

	public void hostlist(PcapAddress addr) {
		byte[] v4addr=addr.getAddress().getAddress();
		byte[] v4mask=addr.getNetmask().getAddress();
		int alen=v4addr.length;
		byte[] netaddr=new byte[alen];
		byte[] broadcast=new byte[alen];
		for(int i=0;i<alen;i++) {
			netaddr[i]=(byte)(v4addr[i]&v4mask[i]);
			broadcast[i] = (byte)(~v4mask[i] | v4addr[i]);
		}

		try {
		InetAddress nx = InetAddress.getByAddress(netaddr);
		System.out.println("netaddr"+nx.getHostAddress());
		InetAddress ny = InetAddress.getByAddress(broadcast);
		System.out.println("broadcast"+ny.getHostAddress());
		int hn=0;
		for(int i=0;i<alen;i++) {
			hn=(hn<<8)|(0xff & ~v4mask[i]);
		}
		InetAddress[] ad = new InetAddress[255];
		for(int i=1;i<hn;i++) {
			byte[] ha=new byte[alen];
			int wm=0xff;
			for(int j=0;j<alen;j++) {
				ha[alen-j-1]=(byte)(i & wm);
				wm=wm<<8;

			}
			byte[] hx=new byte[alen];
			for(int j=0;j<alen;j++) {
				hx[j]=(byte)(ha[j] | netaddr[j]);
			}
			InetAddress hxx=InetAddress.getByAddress(hx);
			System.out.println("host"+hxx);
			ad[i]=hxx;
			Child ch = new Child(hxx,445,this);
		}
			System.out.println("445番ポートスキャン");
}
		catch(Exception e) {
		}
	}
	public synchronized void setOpen(InetAddress a,int p) {
		System.out.println("Open:"+a.toString()+":"+p);
	}
}