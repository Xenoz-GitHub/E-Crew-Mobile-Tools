package com.example.mini;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class ExportedService extends Service {
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
