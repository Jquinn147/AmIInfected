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
        // string cmdArg0 = "\"C:\\Users\\quinn\\Desktop\\Forensic Tools\\Detection\\YARA\\yara64.exe\" "; 
        string cmdArg0;//path to yara exe
        //string cmdArg1 = "\"C:\\Users\\quinn\\Desktop\\Forensic Tools\\Detection\\YARA\\Rules.txt\" ";
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
            Console.WriteLine("Please Input Path to exe: -->");
            cmdArg0 = "\"" + Console.ReadLine() + "\"" + " ";
            Console.WriteLine("\nPlease input path to yara rules");
            cmdArg1 = "\"" + Console.ReadLine() + "\"" + " ";
            
            foreach (Process proc in procs)
            {
                if ((hWnd = proc.MainWindowHandle) != IntPtr.Zero)
                {
                    Console.WriteLine("{0} : {1}", proc.ProcessName, hWnd);
                    Console.WriteLine("PID of {0} : {1}", proc.ProcessName, proc.Id);
                    PID.Add(proc.Id); //Save list of PID's into a int list named PID
                    ProcList.Add(proc.ProcessName); //Save list of PID's into string list 
                    if (proc.ProcessName == "cmd")
                    {
                        procHandle = hWnd; //Injection handle
                    }
                 
                }
            }

            Console.WriteLine("Process Handle2 = {0}", procHandle);
            if (ProcList.Contains("cmd") == false){

                MyProc openProc = new MyProc();
                openProc.OpenApplication("C:\\Windows\\System32\\cmd.exe");
                cmdflag = 1;
                foreach (Process proc in procs)
                {
                    if ((hWnd = proc.MainWindowHandle) != IntPtr.Zero || cmdflag == 1)
                    {
                        Console.WriteLine("{0} : {1}", proc.ProcessName, hWnd);
                        Console.WriteLine("PID of {0} : {1}", proc.ProcessName, proc.Id);
                        PID.Add(proc.Id); //Save list of PID's into a int list named PID
                        ProcList.Add(proc.ProcessName); //Save list of PID's into string list 
                        if (proc.ProcessName == "cmd")
                        {
                            procHandle = hWnd; //Injection handle
                        }
                        cmdflag = 0;
                    }
                }

                //Console.WriteLine("{0} : {1}", Process.ProcessName, procHandle);


            }

            int Fuzznumber = 0; //This function asks is directly after the program lists all open windows, to give you an idea of how high you need to go.
            Console.WriteLine("Max processes to be Fuzzed? -->");//At which point, it attempts to guess the PID's by simply using a loop with exception handlers for Process.GetProcessById(d);
            try
            {
                Fuzznumber = Convert.ToInt32(Console.ReadLine());
            }
            catch
            {
                Console.WriteLine("Error: That's not a number"); //exception handler in case you don't enter a number.
                System.Environment.Exit(0); //I hate exceptions as a malware analyst, but boy are they useful.
            }
            for (int d = 0; d < Fuzznumber; d++) //Here's the start of the loop that tries to guess the PID
            {
              //  var v1 = extfunc.SetForegroundWindow(procHandle);
                var v2 = extfunc.GetLastError(); //I'll probably need this eventually. 
               // Console.WriteLine("SetForeGroundWindow: {0}", v1);
                //Console.WriteLine("Last error code: {0}", v2);
                try
                {
                    
                    Process localbyId = Process.GetProcessById(d);
                    PIDarray.Add(d);
                    Console.WriteLine("Process Name: {0} | PID: {1}\n", localbyId, d);
                    string fileout = String.Format("Process Name: {0} | PID: {1}\n", localbyId, d);
                    File.AppendAllText(masterpath + "\\" + "ProcLog.txt", fileout); //This is the loop to obtain a list of all processes.

                }
                catch (ArgumentException)

                {
                    string console = "Process " + d + " does not exist\n";
                    string Cf = masterpath + "\\" + "Console.txt";
                  //  Console.WriteLine("Process %d does not exist", d);
                    File.AppendAllText(Cf, console); //This txt file contains a list of misc outputs.
                }

                //   // Console.ReadLine();
               
            }
            extfunc.SetForegroundWindow(procHandle);
            SendKeys.SendWait("SET outPath=" + RuleResultfile);
            SendKeys.SendWait("{ENTER}");
            foreach (int item in PIDarray)
            {
                var v1 = extfunc.SetForegroundWindow(procHandle);
                SendKeys.SendWait("SET /A procID=" + item);
                SendKeys.SendWait("{ENTER}");
                
                SendKeys.SendWait(cmdArg0 + cmdArg1 + cmdArg2 + " >> \"{%}outPath{%}\""); //This file contains a list of all of our rule outputs.
                SendKeys.SendWait("{ENTER}");
                
            }


            InitializeComponent();
            System.Threading.Thread.Sleep(1000);
            List<string> RuleReturn = new List<string>();
            string loadfile = "\"" + RuleResultfile + "\"";
            richTextBox1.LoadFile(RuleResultfile, RichTextBoxStreamType.PlainText);
            ParseInputs inputParser = new ParseInputs();
            inputParser.FormatRules(RuleResultfile,out RuleReturn);
           


        }

    
    }
}

public class extfunc
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
                case 10:
                    zx[counter1] = 32;
                    
                    
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

            case 32:
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
        vl1.ForEach(Console.WriteLine);
    }
    
}