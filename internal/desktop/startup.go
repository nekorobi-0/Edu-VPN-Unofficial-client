package desktop

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"unicode/utf16"
)

func taskXML(executable, workingDirectory, sid string) []byte {
	escape := func(s string) string { var b bytes.Buffer; _ = xml.EscapeText(&b, []byte(s)); return b.String() }
	document := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <Triggers><LogonTrigger><UserId>%s</UserId><Delay>PT10S</Delay></LogonTrigger></Triggers>
 <Principals><Principal id="User"><UserId>%s</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
 <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
 <Actions Context="User"><Exec><Command>%s</Command><WorkingDirectory>%s</WorkingDirectory></Exec></Actions>
</Task>`, escape(sid), escape(sid), escape(executable), escape(workingDirectory))
	// schtasks imports task XML as a Unicode document. Keep the declaration,
	// UTF-16LE bytes and BOM consistent, including non-ASCII Windows paths.
	units := utf16.Encode([]rune(document))
	data := make([]byte, 2+2*len(units))
	data[0], data[1] = 0xff, 0xfe
	for i, u := range units {
		binary.LittleEndian.PutUint16(data[2+2*i:], u)
	}
	return data
}
