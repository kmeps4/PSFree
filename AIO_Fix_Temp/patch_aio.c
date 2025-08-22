void patch_aio(void * kbase) {
    //Offsets for 8.0x
    {
        size_t off = 0x9f141;
        u8 patch[] = {0xeb, 0x48};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f183;
        memset(kbase + off, 0x90, 8);
    }
    {
        size_t off = 0x9f18b;
        u8 patch[] = {0x41, 0x83, 0xbf, 0xa0, 0x04, 0x00, 0x00, 0x00};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f199;
        u8 patch[] = {0x49, 0x8b, 0x87, 0xd0, 0x04, 0x00, 0x00};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f1a6;
        u8 patch[] = {0x49, 0x8b, 0xb7, 0xb0, 0x04, 0x00, 0x00};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f1be;
        u8 patch[] = {0x49, 0x8b, 0x87, 0x40, 0x05, 0x00, 0x00};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f1cb;
        u8 patch[] = {0x49, 0x8b, 0xb7, 0x20, 0x05, 0x00, 0x00};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f1e3;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0xc0, 0x00, 0x00, 0x00};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f1ef;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0xe0, 0x00, 0x00, 0x00};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f202;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0x00, 0x01, 0x00, 0x00};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f20e;
        u8 patch[] = {0x49, 0x8d, 0xbf, 0x20, 0x01, 0x00, 0x00};
        memcpy(kbase + off, patch, sizeof patch);
    }
    {
        size_t off = 0x9f21f;
        u8 patch[] = {0x49, 0x8b, 0xff};
        memcpy(kbase + off, patch, sizeof patch);
    }
}
