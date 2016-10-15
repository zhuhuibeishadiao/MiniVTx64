#pragma once
#include "intel_vt_x64.h"

#define MY_DVC_BUFFERED_CODE (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,	FILE_ANY_ACCESS)
#define VT_64_OPEN 0x80010

NTSTATUS MyDeviceIoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS Status;
	HANDLE hThread = NULL;
	PIO_STACK_LOCATION irpSp; //当前IRP调用栈空间   
	ULONG code;               //功能号   
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ULONG inBufLength;        //输入缓冲区长度   
	ULONG outBufLength;       //输出缓冲区长度   
	PCHAR inBuf;              //输入缓冲区   
	PCHAR outBuf;             //输出缓冲区   
	PCHAR outData = "[VTF] 111"; //要向应用层输出的信息   
	ULONG outDataLen = strlen(outData) + 1;  //信息长度含结尾一个NULL   

	DbgPrint("[VTF] GetIoControl\n");

	irpSp = IoGetCurrentIrpStackLocation(Irp);               //获得当前IRP调用栈空间   
	code = irpSp->Parameters.DeviceIoControl.IoControlCode;  //得到功能号，即控制码   
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;   //得到输入缓冲区长度   
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength; //得到输出缓冲区长度   
	inBuf = Irp->AssociatedIrp.SystemBuffer;  //输入缓冲区   
	outBuf = Irp->AssociatedIrp.SystemBuffer; //输出缓冲区   

	if (code == VT_64_OPEN)  //我们自定义的控制码   
	{
		DbgPrint("[VTF] inBuf: %s\n", inBuf);      //打印出应用层传入的内容   

		RtlCopyBytes(outBuf, outData, outBufLength); //复制我们要传入的内容到输出缓冲区   

		Irp->IoStatus.Information = (outBufLength < outDataLen ? outBufLength : outDataLen);
		Status = PsCreateSystemThread(&hThread,
			THREAD_ALL_ACCESS,
			NULL,
			NULL,
			NULL,
			(PKSTART_ROUTINE)VtStart, NULL);
		if (!NT_SUCCESS(Status))
		{
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	}
	else
	{
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT); //结束IRP请求   

	DbgPrint("[VTF] MyDeviceIoControl Over\n");
	return Irp->IoStatus.Status;
}
NTSTATUS MyCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("[VTF] MyCreateClose\n");
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
	CCHAR i;
	KIRQL OldIrql;
	KAFFINITY OldAffinity;

	KeInitializeMutex(&g_mutex, 0);
	KeWaitForSingleObject(&g_mutex, Executive, KernelMode, FALSE, NULL);

	for (i = 0; i < KeNumberProcessors; i++)
	{
		OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1 << i));
		OldIrql = KeRaiseIrqlToDpcLevel();
		_StopVirtualization();
		KeLowerIrql(OldIrql);
		KeRevertToUserAffinityThreadEx(OldAffinity);
	}

	KeReleaseMutex(&g_mutex, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE hThread = NULL;
	FGP_VT_KDPRINT(("Dirver is Start"));
	DriverObject->DriverUnload = DriverUnload;

	Status = PsCreateSystemThread(&hThread,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		(PKSTART_ROUTINE)VtStart, NULL);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	FGP_VT_KDPRINT(("Dirver is Start"));
	//Status = VtStart(NULL);
	return Status;
	//NTSTATUS ntStatus = STATUS_SUCCESS;
	//PDEVICE_OBJECT Device;
	//UNICODE_STRING DeviceName, DeviceLink;  //设备名，符号链接名   

	//DbgPrint("[VTF] DriverEntry\n");

	//RtlInitUnicodeString(&DeviceName, L"\\Device\\VT_64");         //初始化设备名  
	//RtlInitUnicodeString(&DeviceLink, L"\\DosDevices\\VT_64");  //初始化符号链接名  
	////mm_init(DriverObject);
	////p2m_init();
	//EptPml4TablePointer = InitEptIdentityMap();
	//pagingInitMappingOperations(&memContext, 1024);
	///* IoCreateDevice 生成设备对象 */
	//ntStatus = IoCreateDevice(DriverObject,         //生成设备的驱动对象   
	//	0,                    //设备扩展区内存大小   
	//	&DeviceName,          //设备名，/Device/Aliwy   
	//	FILE_DEVICE_UNKNOWN,  //设备类型   
	//	0,                    //填写0即可   
	//	FALSE,                //必须为FALSE   
	//	&Device);             //设备对象指针返回到DeviceObject中   
	//if (!NT_SUCCESS(ntStatus))
	//{
	//	DbgPrint("[VTF] IoCreateDevice FALSE: %.8X\n", ntStatus);
	//	return ntStatus;  //生成失败就返回   
	//}
	//else
	//	DbgPrint("[VTF] IoCreateDevice SUCCESS\n");

	///* IoCreateSymbolicLink 生成符号链接 */
	//ntStatus = IoCreateSymbolicLink(&DeviceLink, &DeviceName);
	//if (!NT_SUCCESS(ntStatus))
	//{
	//	DbgPrint("[VTF] IoCreateSymbolicLink FALSE: %.8X\n", ntStatus);
	//	IoDeleteDevice(Device);  //删除设备   
	//	return ntStatus;
	//}
	//else
	//	DbgPrint("[VTF] IoCreateSymbolicLink SUCCESS\n");

	//Device->Flags &= ~DO_DEVICE_INITIALIZING;  //设备初始化完成标记   

	//DriverObject->DriverUnload = DriverUnload;

	///*设备控制请求，对应Ring3 DeviceIoControl*/
	//DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDeviceIoControl;
	///*设备打开请求，对应Ring3 CreateFile*/                      //   
	//DriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreateClose; //  要与应用层通信，   
	///*设备关闭请求，对应Ring3 CloseHandle*/                     //  必须有打开、关闭请求！   
	//DriverObject->MajorFunction[IRP_MJ_CLOSE] = MyCreateClose;  //    
	//PsSetCreateProcessNotifyRoutine(&processCreationMonitor, FALSE);

	//return ntStatus;
}
