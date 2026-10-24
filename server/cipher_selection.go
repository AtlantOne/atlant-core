package main

func chooseRealityCipher(offered []uint16, modern bool) (uint16, bool) {
	if modern {
		for _, suite := range offered {
			if suite == 0x1301 {
				return suite, true
			}
		}
	}
	for _, suite := range offered {
		if suite == 0x1303 {
			return suite, true
		}
	}
	return 0, false
}
