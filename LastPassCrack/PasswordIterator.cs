using com.mifmif.common.regex;
using net.sf.jni4net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using GenerexUtil = com.mifmif.common.regex.util;


namespace LastPassCrack
{
    public class PasswordIterator
    {
        private GenerexUtil.Iterator iterator;

        public PasswordIterator(string regex)
        {
            var setup = new BridgeSetup();
            setup.Verbose = true;
            setup.AddAllJarsClassPath("./");
            Bridge.CreateJVM(setup);
            Bridge.RegisterAssembly(typeof(Generex).Assembly);
            var generex = new Generex(regex);
            iterator = generex.iterator();
        }

        public bool GetNext(out string password)
        {
            var result = false;
            password = "";
            lock (iterator)
            {
                if(iterator.hasNext())
                {
                    result = true;
                    password = iterator.next();
                }
            }
            return result;
        }
    }
}
