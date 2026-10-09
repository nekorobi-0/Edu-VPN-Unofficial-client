package platform

import (
	"fmt"
	"golang.org/x/sys/windows"
)

func Restrict(path string, dir bool) error {
	t := windows.GetCurrentProcessToken()
	u, e := t.GetTokenUser()
	if e != nil {
		return e
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	sd, e := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;%s;FA;;;SY)(A;%s;FA;;;%s)", inherit, inherit, u.User.Sid.String()))
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func PrepareDriver(path string) error {
	_, e := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	return e
}
