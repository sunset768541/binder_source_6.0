/*
 * Copyright (C) 2006 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.os;

import java.util.ArrayList;


/**
 * Native implementation of the service manager.  Most clients will only
 * care about getDefault() and possibly asInterface().
 * @hide
 */
public abstract class ServiceManagerNative extends Binder implements IServiceManager
{
    /**
     * Cast a Binder object into a service manager interface, generating
     * a proxy if needed.
     */
    static public IServiceManager asInterface(IBinder obj)//IBinder是一个java接口
    {
        if (obj == null) {
            return null;
        }
        IServiceManager in =
            (IServiceManager)obj.queryLocalInterface(descriptor);
        if (in != null) {
            return in;
        }
        
        return new ServiceManagerProxy(obj);//smr大管家的代理类BpBinder(0)
    }
    
    public ServiceManagerNative()
    {
        attachInterface(this, descriptor);
    }
    

    //   ServiceManagerNative.onTransact不会被调用
//在ServiceManagerNative中，它的onTransact方法不会被调用。

//对aidl有一定了解的读者，会知道，在aidl定义的binder对象中，Stub.onTransact和Stub.Proxy中的IBinder.transact 会成对存在。即，当client进程调用了transact之后，server进程会调用到onTransact方法。
//ServiceManager最终逻辑的进程直接就在native层实现了，因此也不需要将逻辑传回java层再做处理。
    //ServiceManagerNative.onTransact不会被调用，在ServiceManagerProxy中调用了IBinder.transact之后，其逻辑直接在native层处理了。
    public boolean onTransact(int code, Parcel data, Parcel reply, int flags)
    {
        try {
            switch (code) {
            case IServiceManager.GET_SERVICE_TRANSACTION: {
                data.enforceInterface(IServiceManager.descriptor);
                String name = data.readString();
                IBinder service = getService(name);
                reply.writeStrongBinder(service);
                return true;
            }
    
            case IServiceManager.CHECK_SERVICE_TRANSACTION: {
                data.enforceInterface(IServiceManager.descriptor);
                String name = data.readString();
                IBinder service = checkService(name);
                reply.writeStrongBinder(service);
                return true;
            }
    
            case IServiceManager.ADD_SERVICE_TRANSACTION: {
                data.enforceInterface(IServiceManager.descriptor);
                String name = data.readString();
                IBinder service = data.readStrongBinder();
                boolean allowIsolated = data.readInt() != 0;
                addService(name, service, allowIsolated);//这个方法的实现是在哪里？ServiceManagerNative是个抽象类，也就是其子类实现了addService的方法
                return true;
            }
    
            case IServiceManager.LIST_SERVICES_TRANSACTION: {
                data.enforceInterface(IServiceManager.descriptor);
                String[] list = listServices();
                reply.writeStringArray(list);
                return true;
            }
            
            case IServiceManager.SET_PERMISSION_CONTROLLER_TRANSACTION: {
                data.enforceInterface(IServiceManager.descriptor);
                IPermissionController controller
                        = IPermissionController.Stub.asInterface(
                                data.readStrongBinder());
                setPermissionController(controller);
                return true;
            }
            }
        } catch (RemoteException e) {
        }
        
        return false;
    }

    public IBinder asBinder()
    {
        return this;
    }
}

class ServiceManagerProxy implements IServiceManager {
    public ServiceManagerProxy(IBinder remote) {
        mRemote = remote;//这个是从service_manger.c中获取的0号Binder
    }
    
    public IBinder asBinder() {
        return mRemote;
    }
    
    public IBinder getService(String name) throws RemoteException {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken(IServiceManager.descriptor);
        data.writeString(name);
        mRemote.transact(GET_SERVICE_TRANSACTION, data, reply, 0);
        IBinder binder = reply.readStrongBinder();
        reply.recycle();
        data.recycle();
        return binder;
    }

    public IBinder checkService(String name) throws RemoteException {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken(IServiceManager.descriptor);
        data.writeString(name);
        mRemote.transact(CHECK_SERVICE_TRANSACTION, data, reply, 0);
        IBinder binder = reply.readStrongBinder();
        reply.recycle();
        data.recycle();
        return binder;
    }

    public void addService(String name, IBinder service, boolean allowIsolated)
            throws RemoteException {//这个是代理类的调用addService的方法
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken(IServiceManager.descriptor);
        data.writeString(name);//写入服务的名字
        data.writeStrongBinder(service);//写入服务的Binder ，后期获取的就是这个Binder调用Parcel的CPP方法，将binder写入
        //data用flat_binder_object数据结构存储用户空间的Binder  Native对象指针
        data.writeInt(allowIsolated ? 1 : 0);
        mRemote.transact(ADD_SERVICE_TRANSACTION, data, reply, 0);
        reply.recycle();
        data.recycle();
    }
    
    public String[] listServices() throws RemoteException {
        ArrayList<String> services = new ArrayList<String>();
        int n = 0;
        while (true) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(IServiceManager.descriptor);
            data.writeInt(n);
            n++;
            try {
                boolean res = mRemote.transact(LIST_SERVICES_TRANSACTION, data, reply, 0);
                if (!res) {
                    break;
                }
            } catch (RuntimeException e) {
                // The result code that is returned by the C++ code can
                // cause the call to throw an exception back instead of
                // returning a nice result...  so eat it here and go on.
                break;
            }
            services.add(reply.readString());
            reply.recycle();
            data.recycle();
        }
        String[] array = new String[services.size()];
        services.toArray(array);
        return array;
    }

    public void setPermissionController(IPermissionController controller)
            throws RemoteException {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken(IServiceManager.descriptor);
        data.writeStrongBinder(controller.asBinder());
        mRemote.transact(SET_PERMISSION_CONTROLLER_TRANSACTION, data, reply, 0);
        reply.recycle();
        data.recycle();
    }

    private IBinder mRemote;
}
