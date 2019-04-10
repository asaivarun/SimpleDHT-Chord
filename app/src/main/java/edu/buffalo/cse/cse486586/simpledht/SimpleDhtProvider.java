package edu.buffalo.cse.cse486586.simpledht;
import android.content.ContentValues;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.List;

import android.content.ContentProvider;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;

import java.net.Socket;
import java.util.Map;
import java.util.TreeMap;

import android.util.Log;

import static android.content.ContentValues.TAG;

public class SimpleDhtProvider extends ContentProvider {
    static final String[] REMOTE_PORT = {"11108", "11112", "11116", "11120", "11124"};
    static final int SERVER_PORT = 10000;
    static String myPort;
    static String portStr;
    static String delimit = ";";
    static String predecessor = null;
    static String successor = null;
    static String predecessor_port;
    static String successor_port;

    static final String key = "key";
    static final String value = "value";
    static String leader_port="11108";
    static final String str = "content://edu.buffalo.cse.cse486586.simpledht.provider";
    Uri uri = Uri.parse(str);
    static String node_id;
    static int local_keys = 0;
    static int my_index;
    static int nodecount=1;
    TreeMap<String, String> nodes = new TreeMap<String, String>();
    ArrayList<String> local_key_list = new ArrayList<String>();
    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        if(selection.equals("*")){
                if(local_key_list.size()!=0 && !node_id.equals(successor_port) ) {
                    try {
                        Log.i(TAG,"S line 67 Sending delete to successor"+successor_port);
                        Socket socket9 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(successor_port));
                        PrintWriter outclient9 = new PrintWriter(socket9.getOutputStream(),
                                true);
                        outclient9.println("Delete"+delimit+selection);
                        BufferedReader bufread9 = new BufferedReader(new InputStreamReader(socket9.getInputStream()));
                        String rec9 = bufread9.readLine();
                        if (rec9.equals("Deleted")) {
                            Log.i(TAG,"D: line 77; Deleted All values from pre "+ predecessor_port);
                            selection="@";
                            socket9.close();
                        }

                    } catch (Exception e) {
                        Log.e(TAG, "D : line 93  Exception can't forward message to successor " + e.getMessage());
                        e.printStackTrace();
                    }

                    }
                }
        if ((selection.equals("*") && node_id.equals(successor_port)) || selection.equals("@")) {
            for (String l : local_key_list) {
                Log.i(TAG,"D: line 66; deleting key : "+l);
                getContext().deleteFile(l);
                local_key_list.remove(l);
            }

        }

        else{

            if(local_key_list.contains(selection)){
                Log.i(TAG," D : line 107 : Found query " + selection+ "and deleted ");
                getContext().deleteFile(selection);
                local_key_list.remove(selection);
            }
            else{
                Log.i(TAG,"Q : line 356 : Sending delete  : " + selection +" to successor  " + successor_port);
                String delete_single="Delete"+delimit+selection;
                try {
                    Socket socket15 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(successor_port));
                    PrintWriter outclient15 = new PrintWriter(socket15.getOutputStream(),
                            true);

                    outclient15.println(delete_single);
                    BufferedReader bufread14 = new BufferedReader(new InputStreamReader(socket15.getInputStream()));
                    String rec14 = bufread14.readLine();
                    if (rec14.equals("Deleted")) {
                        socket15.close();
                    }
                } catch (Exception e) {
                    Log.e(TAG, "S : line 404  Exception can't send updated_prev  " + e.getMessage());
                    e.printStackTrace();
                }
            }
            }

        return 0;
        }


    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        String filename = values.getAsString("key");
        String fileContents = values.getAsString("value");
        Log.i(TAG, "I : : line 121 ; key "+ filename + " Values "+fileContents);
        String gen_key = null;
        try {
            gen_key = genHash(filename);
            Log.i(TAG," I : line 126 gen_hash for key : " +gen_key + " key :" + filename + " value : " + fileContents );
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        boolean check=false;
        try {
            check= keyhash_compare(gen_key);
            Log.i(TAG, " Checked condition fro key: "+ check);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if(check){
                  Log.i(TAG, " I: line 129, Writing the key in this content provider " + gen_key);


                // TODO Auto-generated method stub
                FileOutputStream outputStream;


                try {
                    outputStream = getContext().openFileOutput(filename, Context.MODE_WORLD_WRITEABLE);
                    outputStream.write(fileContents.getBytes());
                    outputStream.close();
                } catch (Exception e) {
                    Log.e(TAG, "I: line 143; File write failed");
                }
                Log.v(TAG,"I : line 145; insert"+values.toString());


            local_keys = local_keys + 1;
            local_key_list.add(filename);
        } else {
            String message="Message"+delimit+gen_key+delimit+filename+delimit+fileContents;
            Log.i(TAG, "I : line 152;  Sending key to next successor with port " + successor_port);
            try {
                Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(successor_port));
                PrintWriter outclient2 = new PrintWriter(socket2.getOutputStream(),
                        true);
                outclient2.println(message);
                BufferedReader bufread2 = new BufferedReader(new InputStreamReader(socket2.getInputStream()));
                String rec2 = bufread2.readLine();
                if (rec2.equals("received")) {
                    Log.i(TAG, "I : line 173; Receied ack and closing socket with " + successor_port);
                    socket2.close();
                }


            } catch (Exception e) {
                Log.e(TAG, "I : line 166  Exception can't forward message to successor " + e.getMessage());
                e.printStackTrace();
            }

        }
        return uri;
    }
    public boolean keyhash_compare(String key_hash) throws NoSuchAlgorithmException {
        Log.i(TAG, " C : line 186 :  keyid : "+key_hash + " node_id : " +node_id+ " predecessor: "+ predecessor + " pre port : "+predecessor_port + " succ port : " + successor_port + " succ : " + successor);
        if(node_id.equals(predecessor))
        {
            return true;
        }
        if((predecessor.compareTo(key_hash)<0 || node_id.compareTo(predecessor)<0) && node_id.compareTo(key_hash)>0)
        {
            return true;
        }
        if(node_id.compareTo(key_hash)<0  && node_id.compareTo(predecessor)<0 && predecessor.compareTo(key_hash)<0)
        {
            return true;
        }
        return false;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
        TelephonyManager tel = (TelephonyManager) this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
        portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(portStr)*2));
        predecessor_port=myPort;
        successor_port=myPort;
        try {
            node_id = genHash(portStr);
            predecessor=genHash(portStr);
            successor=genHash(portStr);
            Log.i(TAG," portStr : "+portStr+" myport :  "+ myPort+ " gen_node id : " +node_id);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, " O : line 184; genHash of myport failed");
            e.printStackTrace();
        }
        Log.i(TAG, "O: line :187 ;  My port is :" + myPort);
        if (myPort.equals(REMOTE_PORT[0])) {
            nodes.put(node_id, myPort);
        }
        else {
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, myPort);
        }

        try {

            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {

            Log.e(TAG, " O : line :201; Can't create a ServerSocket");

        }


        return false;
    }

    public Cursor query_all(String origin_node){
        MatrixCursor matrixcursor = new MatrixCursor(new String[]{"key", "value"});
        if(!successor_port.equals(origin_node)) {
            Log.i(TAG, " Q : line 237 : Sending query * to successor port " + successor_port);
                try {
                    Log.i(TAG, " Q: line 275;  Sending query * to successor port " + successor_port);

                    Socket socket11 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(successor_port));
                    PrintWriter outclient11 = new PrintWriter(socket11.getOutputStream(),
                            true);
                    String send_query="Query"+delimit+origin_node;
                    outclient11.println(send_query);
                    ObjectInputStream obj = new ObjectInputStream(socket11.getInputStream());
                    Object object = null;
                    HashMap<String, String> remote_pairs = new HashMap<String, String>();
                    try {
                        object = obj.readObject();
                    } catch (Exception e) {
                        Log.e(TAG, "Q : line 264; Object read failed " + e.getMessage());
                        e.printStackTrace();
                    }
                    if (object != null) {
                        Log.i(TAG," Received Map from suc "+ successor_port);
                        remote_pairs = (HashMap<String, String>) object;
                        for (Map.Entry eachpair : remote_pairs.entrySet()) {
                            matrixcursor.newRow()
                                    .add("key", eachpair.getKey())
                                    .add("value", eachpair.getValue());
                        }
                        socket11.close();
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Q : line 278;  Exception can't forward message for querying to successor " + e.getMessage());
                    e.printStackTrace();
                }
            }

        return  matrixcursor;
    }
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {
        // TODO Auto-generated method stub

        MatrixCursor matrixcursor = new MatrixCursor(new String[]{"key", "value"});
        if(selection.equals("*")&& !node_id.equals(successor)){
           matrixcursor= (MatrixCursor) query_all(myPort);
           selection="@";
           Log.i(TAG," S: line 283; Returned map to Origin node and new selection is : "+ selection);


        }
        if((selection.equals("*")&& node_id.equals(successor) ) ||selection.equals("@")) {
            Log.i(TAG,"S : line 288; Returning all values from this local node ");
            for (String i:local_key_list) {
                StringBuilder text = new StringBuilder();

                try {
                    FileInputStream InputStream = getContext().openFileInput(i);


                    BufferedReader bufr = new BufferedReader(new InputStreamReader(new BufferedInputStream(InputStream)));

                    String line_value;
                    while ((line_value = bufr.readLine()) != null) {
                        text.append(line_value);
                    }

                    bufr.close();

                } catch (Exception e) {
                    Log.e(TAG, "Q: line 232; File read failedkey = " + i);
                }

                matrixcursor.newRow()
                        .add("key", i)
                        .add("value", text);
                Log.v(TAG,"Q line 238 : query "+ i + " " + text);
            }
        }

        else if (!selection.equals("@") && !selection.equals("*")){

            if(local_key_list.contains(selection)){
                Log.i(TAG," Found query and returned");
                StringBuilder text = new StringBuilder();
                try {

                    FileInputStream InputStream = getContext().openFileInput(selection);


                    BufferedReader bufr = new BufferedReader(new InputStreamReader(new BufferedInputStream(InputStream)));

                    String line_value;
                    while ((line_value = bufr.readLine()) != null) {
                        text.append(line_value);
                    }

                    bufr.close();



                } catch (Exception e) {
                    Log.e(TAG, "Q : line 305;   File read failed" + "key = " + selection);
                }

                matrixcursor.newRow()
                        .add("key", selection)
                        .add("value", text);
                Log.v(TAG,"Q : line 311;   query: "+ selection + " " + text);

        }
        else{
                Log.i(TAG,"Q : line 356 : Sending query : " + selection +" to successor  " + successor_port);
                String query_single="Query_Single"+delimit+selection;
                try {
                    Socket socket14 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(successor_port));
                    PrintWriter outclient14 = new PrintWriter(socket14.getOutputStream(),
                            true);

                    outclient14.println(query_single);
                    BufferedReader bufread14 = new BufferedReader(new InputStreamReader(socket14.getInputStream()));
                    String rec14 = bufread14.readLine();
                    if (rec14!=null) {
                        Log.i(TAG,"Q : line 368 returning key + "+selection+ " value : "+rec14 );
                        matrixcursor.newRow()
                                .add("key", selection)
                                .add("value", rec14);
                        socket14.close();
                    }
                } catch (Exception e) {
                    Log.e(TAG, "S : line 404  Exception can't send updated_prev  " + e.getMessage());
                    e.printStackTrace();
                }



            }



        }
        return matrixcursor;
    }


    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }


    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];

            /*
             * TODO: Fill in your server code that receives messages and passes them
             * to onProgressUpdate().
             */
            try {
                while (true) {
                    try {

                        Socket client = serverSocket.accept();
                        Log.d(TAG, "S:  line 361;  Myport  " + myPort);
                        BufferedReader br = new BufferedReader(new InputStreamReader(
                                client.getInputStream()));
                        String r_data;
                        if ((r_data = br.readLine()) != null) {
                            Log.i(TAG, " S : line 366;  Received msg not null through socket buffer reader is : " + r_data);
                            String[] rec_data = r_data.split(delimit);
                            if(myPort.equals(REMOTE_PORT[0])&& rec_data[0].equals("Join"))
                            {
                                Log.i(TAG, " S: line 391 Adding new node:" +rec_data[1] + " with gen_hash " +rec_data[1] + " to chord ");
                                nodes.put(rec_data[2],rec_data[1]);
                                nodecount++;
                                if(nodecount>1){
                                    Log.i(TAG," S: line 395 entered  node count : " + nodecount +"is > 1 ");
                                    List<String> node_genkey_list = new ArrayList<String>(nodes.keySet());
                                    my_index=node_genkey_list.indexOf(rec_data[2]);
                                    Log.i(TAG," S: line 429; my index is : "+my_index);
                                    String newnode_suc_pre;
                                    String update_node_pre="Update_Predecessor"+delimit+rec_data[2]+delimit+rec_data[1];
                                    String update_node_suc="Update_Successor"+delimit+rec_data[2]+delimit+rec_data[1];
                                    String update_pre_port;
                                    String update_suc_port;

                                    if(nodecount>2) {
                                        int successor_index;
                                        if(my_index==(nodecount-1)) {
                                            successor_index = 0;
                                        }else {
                                            successor_index = my_index + 1;
                                        }
                                        int predecessor_index;
                                        if (my_index==0){
                                            predecessor_index=(nodecount-1);
                                        }
                                        else{
                                            predecessor_index=my_index-1;
                                        }
                                        Log.i(TAG," S: line 429; pre index is : "+predecessor_index+ " suc index is : " + successor_index);
                                        newnode_suc_pre = node_genkey_list.get(predecessor_index) + delimit + nodes.get(node_genkey_list.get(predecessor_index)) + delimit + node_genkey_list.get(successor_index) + delimit + nodes.get(node_genkey_list.get(successor_index));
                                        update_pre_port=nodes.get(node_genkey_list.get(successor_index));
                                        update_suc_port=nodes.get(node_genkey_list.get(predecessor_index));
                                        //Send updated predecessor to update_pre_port
                                        if(update_pre_port.equals(myPort)){
                                            predecessor_port =rec_data[1];
                                            predecessor =rec_data[2];
                                        }
                                        else if(!update_node_pre.equals(myPort)) {
                                            try {
                                                Log.i(TAG,"S : line 461 : Send updated predecessor to update_pre_port " + update_pre_port);
                                                Socket socket4 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                                        Integer.parseInt(update_pre_port));
                                                PrintWriter outclient4 = new PrintWriter(socket4.getOutputStream(),
                                                        true);

                                                outclient4.println(update_node_pre);
                                                BufferedReader bufread4 = new BufferedReader(new InputStreamReader(socket4.getInputStream()));
                                                String rec4 = bufread4.readLine();
                                                if (rec4.equals("received")) {
                                                    socket4.close();
                                                }
                                            } catch (Exception e) {
                                                Log.e(TAG, "S : line 404  Exception can't send updated_prev  " + e.getMessage());
                                                e.printStackTrace();
                                            }
                                        }
                                        if(update_suc_port.equals(myPort)){
                                            successor_port =rec_data[1];
                                            successor =rec_data[2];
                                        }
                                        else if(!update_suc_port.equals(myPort)) {
                                        //Send updated successor to update_suc_port
                                        try {
                                            Log.i(TAG, "S : line 415; Sending Updated Successor to "+ update_suc_port);
                                            Socket socket5 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                                    Integer.parseInt(update_suc_port));
                                            PrintWriter outclient5 = new PrintWriter(socket5.getOutputStream(),
                                                    true);
                                            outclient5.println(update_node_suc);
                                            BufferedReader bufread5 = new BufferedReader(new InputStreamReader(socket5.getInputStream()));
                                            String rec5 = bufread5.readLine();
                                            if (rec5.equals("received")) {
                                                socket5.close();
                                            }
                                        } catch (Exception e) {
                                            Log.e(TAG, "S : line 427;  Exception can't send updated_suc to " + e.getMessage());
                                            e.printStackTrace();
                                        }
                                    }
                                    }
                                    else {
                                        Log.i(TAG, " S : Line 432; node count == 2 ");
                                        newnode_suc_pre =node_id + delimit + myPort + delimit + node_id + delimit + myPort;
                                        predecessor_port =rec_data[1];
                                        predecessor =rec_data[2];
                                        successor_port =rec_data[1];
                                        successor =rec_data[2];

                                    }
                                    PrintWriter outclient3 = new PrintWriter(client.getOutputStream(),
                                            true);
                                    outclient3.println(newnode_suc_pre);

                                }

                            }

                            if (rec_data[0].equals("Message")) {
                                Log.i(TAG, " S: line 449, sending msg to  content provider for inserting " + rec_data[1]);
                                PrintWriter outclient8 = new PrintWriter(client.getOutputStream(),
                                        true);
                                outclient8.println("received");
                                ContentValues keyValueToInsert = new ContentValues();
                                keyValueToInsert.put(key, rec_data[2]);
                                keyValueToInsert.put(value, rec_data[3]);

                                uri = insert(uri, keyValueToInsert);
                            }
                            if (rec_data[0].equals("Update_Predecessor")) {
                                predecessor = rec_data[1];
                                predecessor_port = rec_data[2];
                                Log.i(TAG, "S : line:462;  new predecessor : " + predecessor_port );
                                PrintWriter outclient6 = new PrintWriter(client.getOutputStream(),
                                        true);
                                outclient6.println("received");
                            }

                            if (rec_data[0].equals("Update_Successor")) {
                                successor = rec_data[1];
                                successor_port = rec_data[2];
                                Log.i(TAG, "S: line 471  new predecessor : " + successor_port);
                                PrintWriter outclient7 = new PrintWriter(client.getOutputStream(),
                                        true);
                                outclient7.println("received");

                            }
                            if (rec_data[0].equals("Delete")) {
                                delete(uri,rec_data[1],null);
                                Log.i(TAG, "S: 479 deleting "+ rec_data[1]+ " values in this node " );
                                PrintWriter outclient10 = new PrintWriter(client.getOutputStream(),
                                        true);
                                outclient10.println("Deleted");

                            }
                            if (rec_data[0].equals("Query")) {
                                HashMap<String,String>pairs_map = new HashMap<String, String>();
                                Cursor matrixcursor_suc;
                                matrixcursor_suc= query_all( rec_data[1]);
                                while(matrixcursor_suc.moveToNext()){
                                    pairs_map.put(matrixcursor_suc.getString(0),matrixcursor_suc.getString(1));
                                }
                                Log.i(TAG," S: line 571 Received queries from successor");
                                Cursor matrixcursor_local;
                                matrixcursor_local= query(uri, null, "@", null, null);
                                while(matrixcursor_local.moveToNext()){
                                    pairs_map.put(matrixcursor_local.getString(matrixcursor_local.getColumnIndex("key")),matrixcursor_local.getString(matrixcursor_local.getColumnIndex("value")));
                                }
                                Log.i(TAG," S: line 577 Returning Map to pre : "+predecessor_port);
                                ObjectOutputStream outclient12 = new ObjectOutputStream(client.getOutputStream());
                                outclient12.writeObject(pairs_map);

                            }
                            if (rec_data[0].equals("Query_Single")) {
                                PrintWriter outclient13 = new PrintWriter(client.getOutputStream(),
                                        true);
                                Log.i(TAG,"S : line 590 In query single, querying :"+rec_data[1]);
                                Cursor matrixcursor_single ;
                                matrixcursor_single= query(uri, null, rec_data[1], null, null);
                                matrixcursor_single.moveToFirst();
                                Log.i(TAG,  "S line 593; mcs key : " + matrixcursor_single.getString(0)  + "mcs key : " + matrixcursor_single.getString(1));
                                String found_query=matrixcursor_single.getString(1);
                                Log.i(TAG, "S: line 551 Found query " +found_query );
                                outclient13.println(found_query);

                            }

                        }

                    } catch (Exception e) {
                        Log.e(TAG, "S : line 499 ; Can't listen on ServerSocket " + e.getMessage());
                        e.printStackTrace();
                    }


                    Log.i(TAG," S: 527  Server Running dude ");
                }
            } catch (Exception e) {
                Log.e(TAG, "S: line 507; Can't listen on ServerSocket " + e.getMessage());
                e.printStackTrace();
            }


            return null;
        }

    }
    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... msgs) {

            try {

                String data = "Join" + delimit + myPort + delimit + node_id  ;
                        Socket socket3 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(leader_port));
                        Log.i(TAG, "C : Line 525, Connected to server with port to notify leader about node join " + leader_port + " from port " + myPort);
                        try {                            // format TORTURE REQUESTING_PORT

                            PrintWriter outclient = new PrintWriter(socket3.getOutputStream(),
                                    true);
                            outclient.println(data);

                            Log.d(TAG, "C : Line 532, sent data " + data +" port to " +portStr+ " leader  port " + leader_port);
                            BufferedReader bufread = new BufferedReader(new InputStreamReader(socket3.getInputStream()));
                            String rec = bufread.readLine();
                            if (rec!=null) {
                                String[] rec_data1 = rec.split(delimit);
                                predecessor =rec_data1[0];
                                predecessor_port =rec_data1[1];
                                successor =rec_data1[2];
                                successor_port =rec_data1[3];
                                Log.i(TAG, " C: Line 541, Joined node with leader as avd0 and suc port"+successor_port+ " pre port " + predecessor_port);
                                socket3.close();
                            }
                        } catch (Exception e) {
                            Log.e(TAG, "C : Line 545,  Client not sending port num to leader " + e.getMessage());
                            e.printStackTrace();
                        }

            }catch (Exception e) {
                Log.e(TAG, "C : line 550; Socket connetion to leader port failed " + e.getMessage());
                e.printStackTrace();
            }
            return null;
        }
    }



}
/*References
https://docs.oracle.com/javase/8/docs/api/java/util/PriorityQueue.html
https://docs.oracle.com/javase/8/docs/api/java/net/Socket.html#setSoTimeout-int-4
https://developer.android.com/reference/java/net/Socket
https://developer.android.com/reference/java/lang/Exception
https://docs.oracle.com/javase/8/docs/api/java/net/Socket.html
https://docs.oracle.com/javase/8/docs/api/java/util/ArrayList.html
https://docs.oracle.com/javase/8/docs/api/java/lang/String.html
https://docs.oracle.com/javase/8/docs/api/java/io/BufferedReader.html
https://docs.oracle.com/javase/8/docs/api/java/io/PrintWriter.html
https://docs.oracle.com/javase/8/docs/api/java/util/TreeMap.html
https://docs.oracle.com/javase/8/docs/api/java/util/List.html
https://developer.android.com/reference/android/database/MatrixCursor.html
 */