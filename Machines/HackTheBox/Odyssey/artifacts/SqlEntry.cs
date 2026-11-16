using System;
using System.Data.SqlTypes;
using System.IO;
using System.Reflection;
using Microsoft.SqlServer.Server;

namespace AuditWorker
{
    public class SqlEntry
    {
        [SqlProcedure]
        public static void Execute(SqlString command)
        {
            TextWriter original = Console.Out;
            StringWriter captured = new StringWriter();
            Console.SetOut(captured);
            try
            {
                MethodInfo main = typeof(Program).GetMethod(
                    "Main",
                    BindingFlags.Static | BindingFlags.NonPublic
                );
                main.Invoke(null, new object[] { new string[] { "-cmd", command.Value } });
            }
            catch (Exception error)
            {
                captured.WriteLine(error.ToString());
            }
            finally
            {
                Console.SetOut(original);
            }
            SqlContext.Pipe.Send(captured.ToString());
        }
    }
}
