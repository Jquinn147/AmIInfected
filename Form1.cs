using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;


namespace GetHandle

{
    public partial class Form1 : Form
    {
        IntPtr procHandle;
        string path1;
        string cmdPath;
        string cmdArg0;//path to yara exe
        string cmdArg1; //path to Rules
        string cmdArg2 = "{%}procID{%}"; //%ProcId%
        string x;
        int cmdflag = 0;
        string output;
        int counter = 0;
        int flag = 0;
        string outputFile;
        string consoleFile;
        string RuleResultfile;
        string masterpath;
        List<int> PIDarray = new List<int>();
        int pidCounter = 0;
        public Form1()
        {
            Console.WriteLine("Please Input path to folder to save output, console, and ruleresult");
            masterpath = Console.ReadLine();
            outputFile = "\"" + masterpath + "\\"  + "output.txt" + "\"";
            consoleFile =masterpath + "\\" + "Console.txt" ;
            RuleResultfile =  masterpath + "\\" + "RuleResult.txt";



            if (File.Exists(outputFile)) //Check If files exist and delete
            {
                File.Delete(outputFile);
            }
            if (File.Exists(consoleFile))
            {
                File.Delete(consoleFile);
            }
            if (File.Exists(RuleResultfile))
            {
                File.Delete(RuleResultfile);
               
            }
            if (File.Exists(masterpath + "\\" + "ProcLog.txt"))
            {
                File.Delete(masterpath + "\\" + "ProcLog.txt");
          }

            var PID = new List<int>();
            var ProcList = new List<string>();
        
            Process[] procs = Process.GetProcesses(); //Returns an array of all open processes into procs
            IntPtr hWnd;
            Console.WriteLine("Please Input Path to YARA exe: -->");
            cmdArg0 = "\"" + Console.ReadLine() + "\"" + " ";
            Console.WriteLine("\nPlease input path to yara rules: -->");
            cmdArg1 = "\"" + Console.ReadLine() + "\"" + " ";
            
            foreach (Process proc in procs)
            {
                if ((hWnd = proc.MainWindowHandle) != IntPtr.Zero)
                //set Window Handle variable (hWnd) = proc.MainWindowHandle and then if not zero, continue.
                {
                    Console.WriteLine("{0} : {1}", proc.ProcessName, hWnd); //Process Name, Handle
                    Console.WriteLine("PID of {0} : {1}", proc.ProcessName, proc.Id); //Process Name, PID
                    PID.Add(proc.Id); //Save list of PID's into a int list named PID for each PID found
                    ProcList.Add(proc.ProcessName); //Save list of PID's into string list 
                    if (proc.ProcessName == "cmd") //If you already have CMD open, GREAT! it locates it and injects the necessary commands.
                    //FOR THE LOVE OF ALL THAT IS HOLY AND SACRED, DO NOT CLOSE WHICHEVER CMD WINDOW IT OPENS TO END IT. Closing the program itself will end it just fine
                    {
                        procHandle = hWnd;
                        extfunc.SetForegroundWindow(procHandle);
                        System.Threading.Thread.Sleep(100);
                        SendKeys.SendWait("SET outPath=" + RuleResultfile);
                        SendKeys.SendWait("{ENTER}");//Injection handle
                        SendKeys.SendWait("SET cmd0=" + cmdArg0);
                        SendKeys.SendWait("{ENTER}");
                        SendKeys.SendWait("SET cmd1=" + cmdArg1);
                        SendKeys.SendWait("{ENTER}");
                    }
                 
                }
            }

            //Console.WriteLine("Process Handle2 = {0}", procHandle);
            if (ProcList.Contains("cmd") == false){ //CMD creation and injection
                int whilecount = 1;
               
                    MyProc openProc = new MyProc();
                    openProc.OpenApplication("C:\\Windows\\System32\\cmd.exe"); //path to CMD. Change if that's not yours.
                    cmdflag = 1; //Flag used 
                    System.Threading.Thread.Sleep(1000);
                while (whilecount == 1)
                {
                   Process[] procs1 = Process.GetProcesses();
                    foreach (Process proc in procs1)
                    {
                        if ((hWnd = proc.MainWindowHandle) != IntPtr.Zero || cmdflag == 1)
                        {
                            Console.WriteLine("{0} : {1}", proc.ProcessName, hWnd);
                            Console.WriteLine("PID of {0} : {1}", proc.ProcessName, proc.Id);
                            PID.Add(proc.Id); //Save list of PID's into a int list named PID
                            ProcList.Add(proc.ProcessName); //Save list of PID's into string list 
                            if (proc.MainWindowTitle == "C:\\Windows\\System32\\cmd.exe" || proc.MainWindowTitle == "Administrator: C:\\Windows\\System32\\cmd.exe")
                            {
                                procHandle = hWnd;
                                extfunc.SetForegroundWindow(procHandle);
                                System.Threading.Thread.Sleep(100);
                                SendKeys.SendWait("SET outPath=" + RuleResultfile);
                                SendKeys.SendWait("{ENTER}");//Injection handle
                                SendKeys.SendWait("SET cmd0=" + cmdArg0);
                                SendKeys.SendWait("{ENTER}");
                                SendKeys.SendWait("SET cmd1=" + cmdArg1);
                                SendKeys.SendWait("{ENTER}");
                                whilecount = 0;

                            }
                            cmdflag = 0;
                        }
                    }

                }

            }

            int Fuzznumber = 0; //While GetProcess gets most of the processes, it doesn't get ALL of them. However, its still useful to see how high you need to fuzz. I shoot for 10k over the highest process revealed by GetProcess.
            Console.WriteLine("Max processes to be Fuzzed? -->");//Using output from GetProcess, Enter in Highest PID to fuzz
            try
            {
                Fuzznumber = Convert.ToInt32(Console.ReadLine()); //Basic error checking loop
            }
            catch
            {
                Console.WriteLine("Error: That's not a number"); //exception handler in case you don't enter a number.
                System.Environment.Exit(0); //I hate exceptions as a malware analyst, but boy are they useful.
            }
            for (int d = 0; d <= Fuzznumber; d++) //Here's the start of the loop that tries to guess the PID
            {
              
                var v2 = extfunc.GetLastError(); //I'll probably need this eventually. 
               
                try //Exception Handler for if GetProcessByID fails
                {
                    //If Successful
                    Process localbyId = Process.GetProcessById(d); 
                    PIDarray.Add(d); //Add PID to list of PID's
                    Console.WriteLine("Process Name: {0} | PID: {1}\n", localbyId, d);
                    string fileout = String.Format("Process Name: {0} | PID: {1}\n", localbyId, d); //Write to console and File successful PID
                    File.AppendAllText(masterpath + "\\" + "ProcLog.txt", fileout); //This is the loop to obtain a list of all processes.

                }
                catch (ArgumentException)

                {
                //If Fail
                    string console = "Process " + d + " does not exist\n";
                    string Cf = masterpath + "\\" + "Console.txt";
                  //  Console.WriteLine("Process %d does not exist", d);
                    File.AppendAllText(Cf, console); //This txt file contains a list of misc outputs.
                }

                //   // Console.ReadLine();
               
            }
            
            foreach (int item in PIDarray) //FOR each PID in PIDarray
            {
                var v1 = extfunc.SetForegroundWindow(procHandle); //Set CMD as active window
                //Use sendkeys to send commands to CMD.
                SendKeys.SendWait("SET /A procID=" + item);
                SendKeys.SendWait("{ENTER}");
                //In the above, %procID% = PID in list
                //In the below, cmd0 = [Path to Yara exe] , cmd1 = [Yara Rule List] , procId, [Output Directory]/RuleResult.txt
                SendKeys.SendWait("{%}cmd0{%}" + " " + "{%}cmd1{%}" +" " + "{%}procID{%}" + " >> \"{%}outPath{%}\""); //RuleResult.txt in your Output directory contains a list of all of our rule outputs.
                SendKeys.SendWait("{ENTER}");
                
            }


            InitializeComponent();
            System.Threading.Thread.Sleep(10000);
            
            //Early version of visual output
            List<string> RuleReturn = new List<string>();
            string loadfile = "\"" + RuleResultfile + "\"";
            richTextBox1.LoadFile(RuleResultfile, RichTextBoxStreamType.PlainText);
            ParseInputs inputParser = new ParseInputs();
            inputParser.FormatRules(RuleResultfile,out RuleReturn);
           


        }

    
    }
}

public class extfunc //Imports from various Windows Libraries
{
    public delegate bool EnumDelegate(IntPtr hwnd, int lParam); //Filter

    //User32 Imports
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", EntryPoint = "GetWindowText", //Grab Window Text
        ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int GetWindowText(IntPtr hwnd, StringBuilder lpWindowText, int nMaxCount);
    [DllImport("user32.dll", EntryPoint = "EnumDesktopWindows", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool EnumDesktopWindows(IntPtr hdesktop, EnumDelegate lpEnumCallbackFunction, IntPtr lparam);
    [DllImport("user32.dll", EntryPoint = "GetForegroundWindow", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", EntryPoint = "SetForegroundWindow", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    //kernel32 imports
    [DllImport("kernel32.dll", EntryPoint = "GetLastError", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern uint GetLastError();

    [DllImport("kernel32.dll", EntryPoint = "GetProcessId", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int GetProcessId(IntPtr handle);

    


}
class MyProc
{
     public void OpenApplication(string ApplicationPath)
    {
        Process pProcess = new Process();
      //  pProcess.StartInfo.Arguments = Arguments;
        pProcess.StartInfo.UseShellExecute = false;
        pProcess.StartInfo.RedirectStandardOutput = true;

        Process.Start(ApplicationPath);
       // output = pProcess.StandardOutput.ReadToEnd();
     //   pProcess.WaitForExit();
    }

}
class ParseInputs
{
    public void FormatRules(string LoadFile, out List<string> vl1)
    {
        
        byte[] FileText = File.ReadAllBytes(LoadFile);
        int flag = 0;
        int counter1 = 0;
        int counter2 = 0;
        byte[] a = FileText;
        byte[] zx = a;
        string cString;

        List<string> vs = new List<string>();
        foreach (byte b in a)
        {
            byte c = 0x00;
            c = b;
            
                
            switch (c)
            {
                case 10: //0x0A or "carriage-return". end of line = end of file output.
                    zx[counter1] = 32; //Set = to 0x20, which is much easier to work with
                    
                    
                    break;
                
                    
                 
                default:
                    
                    break;

            }
            counter1++;
            counter2++;

            
        }
        counter1 = 0;
        counter2 = 0;
        vl1 = new List<string>();
        
        foreach (byte b in zx)
        {
            int loopcount = 0;
           
            switch (b)
          
            { 

            case 32: //I really don't want to explain this. but essentially uses 0x20 as a delimiter.
                    //As there are now 2 0x20's here (1 before the ResultValue portion and 1 at end of Result)
                    //We need the second one. this is where int flag comes in. Flag = 0, first 0x20 is encountered. set flag = 1. run loop again, encounter 2nd 0x20 AND flag = 1. discover size of string, create character array to that size and load value into it. save character array as string.
                    //cont from above: Write newly created string to output list
                   
                    zx[counter1] = b;
                     char[] cArray = { 'a' };


                    if (flag == 1)
                    {
                        cArray = new char[counter2];
                        int lc = counter1 - counter2;
                        if (zx[lc] == 32)
                        {
                            System.Threading.Thread.Sleep(100);
                            lc = lc + 1;
                            counter2 = counter2 - 1;
                            cArray = new char[counter2];
                            System.Threading.Thread.Sleep(100);
                        }
                        for (int c1 = 0; c1 < counter2; c1++)
                        {

                            char cChar = (char)zx[lc]; //These functions essentially break each input into its own string
                            cArray[c1] = cChar;
                            lc++;

                        }
                        cString = new string(cArray);
                        // Console.WriteLine(cString);
                        vl1.Add(cString);
                        counter2 = 0;
                       
                        flag = 0;

            }

                    else
                        {
                flag = 1;
                /* Comment Out this else loop and the if loop
                 *  That corresponds with it to get 2 strings, rule and result
                 *  */
            }
            // counter2 = 0;


            break;
                default:
                    break;
            }
            counter1++;
            counter2++;

        }
        vl1.ForEach(Console.WriteLine); //Output each result
    }
    
}
