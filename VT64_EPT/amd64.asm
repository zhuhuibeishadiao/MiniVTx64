
EXTERN StartVirtualization:PROC  
EXTERN ResumeGuest:PROC  
EXTERN HandleVmExit:PROC  

.CODE

_ReadMsr PROC
;	xor		rax, rax
	rdmsr				; MSR[ecx] --> edx:eax
	shl		rdx, 32
	or		rax, rdx
	ret
_ReadMsr ENDP

_WriteMsr PROC
	mov		rax, rdx
	shr		rdx, 32
	wrmsr
	ret
_WriteMsr ENDP

_TSC PROC
;	rdtscp
	rdtsc
	shl		rdx, 32
	or		rax, rdx
	ret
_TSC ENDP

_Rax PROC
	mov		rax, rax
	ret
_Rax ENDP


_Rbx PROC
	mov		rax, rbx
	ret
_Rbx ENDP


_Cs PROC
	mov		rax, cs
	ret
_Cs ENDP

_Ds PROC
	mov		rax, ds
	ret
_Ds ENDP

_Es PROC
	mov		rax, es
	ret
_Es ENDP

_Ss PROC
	mov		rax, ss
	ret
_Ss ENDP

_Fs PROC
	mov		rax, fs
	ret
_Fs ENDP

_Gs PROC
	mov		rax, gs
	ret
_Gs ENDP

_Cr0 PROC
	mov		rax, cr0
	ret
_Cr0 ENDP

_Cr2 PROC
	mov		rax, cr2
	ret
_Cr2 ENDP

_SetCr2 PROC
    mov cr2, rcx
    ret
_SetCr2 ENDP    

_Cr3 PROC
	mov		rax, cr3
	ret
_Cr3 ENDP

_SetCr3 PROC
	mov		cr3, rcx
	ret
_SetCr3 ENDP

_Cr4 PROC
	mov		rax, cr4
	ret
_Cr4 ENDP

_SetCr4 PROC 
	mov rax,cr4
	or  rcx,rax
	mov cr4,rcx	
	ret
_SetCr4 ENDP

_Cr8 PROC
	mov		rax, cr8
	ret
_Cr8 ENDP

_SetCr8 PROC
	mov		cr8, rcx
	ret
_SetCr8 ENDP

_Dr6 PROC
	mov		rax, dr6
	ret
_Dr6 ENDP

_Dr0 PROC
	mov		rax, dr0
	ret
_Dr0 ENDP

_Dr1 PROC
	mov		rax, dr1
	ret
_Dr1 ENDP

_Dr2 PROC
	mov		rax, dr2
	ret
_Dr2 ENDP

_Dr3 PROC
	mov		rax, dr3
	ret
_Dr3 ENDP

_SetDr0 PROC
	mov		dr0, rcx
	ret
_SetDr0 ENDP

_SetDr1 PROC
	mov		dr1, rcx
	ret
_SetDr1 ENDP

_SetDr2 PROC
	mov		dr2, rcx
	ret
_SetDr2 ENDP

_SetDr3 PROC
	mov		dr3, rcx
	ret
_SetDr3 ENDP

_SetDr6 PROC
	mov		dr6, rcx
	ret
_SetDr6 ENDP

_Rflags PROC
	pushfq
	pop		rax
	ret
_Rflags ENDP

_Rsp PROC
	mov		rax, rsp
	add		rax, 8
	ret
_Rsp ENDP

_IdtBase PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		rax, QWORD PTR idtr[2]
	ret
_IdtBase ENDP

_IdtLimit PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		ax, WORD PTR idtr[0]
	ret
_IdtLimit ENDP

_GdtBase PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		rax, QWORD PTR gdtr[2]
	ret
_GdtBase ENDP

_GdtLimit PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
_GdtLimit ENDP

_Ldtr PROC
	sldt	rax
	ret
_Ldtr ENDP

_TrSelector PROC
	str	rax
	ret
_TrSelector ENDP

_CpuId PROC
	push	rbp
	mov		rbp, rsp
	push	rbx
	push	rsi

	mov		[rbp+18h], rdx
	mov		eax, ecx
	cpuid
	mov		rsi, [rbp+18h]
	mov		[rsi], eax
	mov		[r8], ebx
	mov		[r9], ecx
	mov		rsi, [rbp+30h]
	mov		[rsi], edx	

	pop		rsi
	pop		rbx
	mov		rsp, rbp
	pop		rbp
	ret
_CpuId ENDP

_VmxOn PROC
    push rcx
    mov rax, rsp
	vmxon qword ptr [rax]
    pop rcx
	ret
_VmxOn ENDP

_VmxOff PROC
    vmxoff
    mov rsp, rdx
    push rcx
    ret
_VmxOff ENDP

_ReadVMCS PROC
    vmread rdx, rcx
    mov rax, rdx
    ret
_ReadVMCS ENDP

Asm_ReadMsr		Proc
	xor rax,rax
	xor rdx,rdx
	rdmsr
	shl rdx,32
	or rax,rdx
	ret
Asm_ReadMsr		Endp

_WriteVMCS PROC
    vmwrite rcx, rdx
    ret
_WriteVMCS ENDP

Vmx_VmWrite Proc
	mov rax,rcx
	mov rcx,rdx
	vmwrite rax,rcx
	ret
Vmx_VmWrite endp

_VmFailInvalid PROC
    pushfq
    pop rax
    xor rcx, rcx
    bt eax, 0 ; RFLAGS.CF
    adc cl, cl
    mov rax, rcx
    ret
_VmFailInvalid ENDP

_VmFailValid PROC
    pushfq
    pop rax
    xor rcx, rcx
    bt eax, 6 ; RFLAGS.ZF
    adc cl, cl
    mov rax, rcx
    ret
_VmFailValid ENDP    

_VmClear PROC
    push rcx
    mov rax, rsp
	vmclear qword ptr [rax]
    pop rcx
    ret
_VmClear ENDP

_VmPtrLd PROC
    push rcx
    mov rax, rsp
    vmptrld qword ptr [rax]
    pop rcx
    ret
_VmPtrLd ENDP

_VmPtrSt PROC
    push rcx
    mov rax, rsp
    vmptrst qword ptr [rax]
    pop rcx
    ret
_VmPtrSt ENDP

_VmLaunch PROC
    vmlaunch
    ret
_VmLaunch ENDP

_VmResume PROC
    vmresume
    ret
_VmResume ENDP

_StartVirtualization PROC
    ;int 3
	push	rax
	push	rcx
	push	rdx
	push	rbx
	push	rbp
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15

	sub	rsp, 28h

	mov	rcx, rsp
	call	StartVirtualization
_StartVirtualization ENDP

_GuestEntryPoint PROC

	call	ResumeGuest

	add	rsp, 28h

	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rbp
	pop	rbx
	pop	rdx
	pop	rcx
	pop	rax
	ret

_GuestEntryPoint ENDP    

_StopVirtualization PROC
    push rax
    push rbx
    xor rax, rax
    xor rbx, rbx
    mov eax, 42424242h
    mov ebx, 43434343h
    vmcall
_StopVirtualization ENDP    

_InitSplit PROC
	push rax
	push rbx
    xor rax, rax
    xor rbx, rbx
	mov eax,ecx
	mov rbx,rdx
	vmcall
	pop rbx
	pop rax
	ret
_InitSplit ENDP
	

_SetMeasure PROC
	push rax
	push rbx
    xor rax, rax
    xor rbx, rbx
	mov eax,ecx
	mov rbx,rdx
	mov rcx,r8
	vmcall
	pop rbx
	pop rax
	ret
_SetMeasure ENDP

_GuestExit PROC
    pop rbx
    pop rax
    ret
_GuestExit ENDP

_ExitHandler PROC   

	push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push rbp    ; rsp ???
    push rbx
    push rdx
    push rcx
    push rax
    
    mov rax, dr7
    push rax
    mov rax, dr6
    push rax
    mov rax, dr3
    push rax  
    mov rax, dr2
    push rax
    mov rax, dr1
    push rax    
    mov rax, dr0
    push rax	
	
	
	mov rcx, [rsp + 80h] ;PCPU
	mov rdx, rsp		;GuestRegs
	sub	rsp, 28h

	call HandleVmExit	
	add	rsp, 28h
	
	pop rax
	mov dr0, rax
	pop rax
	mov dr1, rax
	pop rax
	mov dr2, rax
	pop rax
	mov dr3, rax
	pop rax
	mov dr6, rax
	pop rax
	mov dr7, rax
	
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
	
	vmresume
	ret

_ExitHandler ENDP

_Int3 PROC
    int 3
    ret
_Int3 ENDP    

_Invd PROC
    invd
    ret
_Invd ENDP    

_InvalidatePage PROC
    invlpg [rcx]
    ret
_InvalidatePage ENDP

_ClearInterrupts PROC
    cli
    ret
_ClearInterrupts ENDP

_SetInterrupts PROC
    sti
    ret
_SetInterrupts ENDP

_InitSpinLock PROC
    and dword ptr [rcx], 0
    ret
_InitSpinLock ENDP

_AcquireSpinLock PROC
    loopspin:
        lock bts dword ptr [rcx], 0
        jb loopspin
    ret
_AcquireSpinLock ENDP

_ReleaseSpinLock PROC
    lock btr dword ptr [rcx], 0
    ret
_ReleaseSpinLock ENDP

_GetMaxPhyaddr PROC
	movzx ecx, cl       
    xor eax, eax
    xor edx, edx
    and ecx, 1Fh                                    ; È¡³ý 32 µÄÓàÊý
    dec eax                                         ; eax = -1£¨FFFFFFFFh)
    shld edx, eax, cl                               ; edx = n1
	shl rdx,20h
	or rax,rdx
    ret

_GetMaxPhyaddr ENDP

_RushTLB PROC
	mov rax,cr3
	mov cr3,rax
	ret
_RushTLB ENDP

_EptInvept PROC
	invept  ecx, xmmword ptr [ebx]
	ret
_EptInvept ENDP

_spin_lock_init PROC 
	mov	rax,rcx
	and	dword ptr [rax], 0
	ret
_spin_lock_init ENDP

_spin_lock_acquire PROC 
	mov	rax, rcx
	cli
loop_down:
	lock	bts dword ptr [rax], 0
	jb	loop_down
	ret
_spin_lock_acquire ENDP

_spin_lock_release PROC 
	mov	rax, rcx
	lock	btr dword ptr [rax], 0
	sti
	ret
_spin_lock_release ENDP

_invept PROC
	mov rax,rdx
	invept  rcx, xmmword ptr [rax]
	ret
_invept ENDP

_invvpid PROC
	mov rax,rdx
	invvpid rcx, xmmword ptr [rax]
	ret
_invvpid ENDP

CPU_LOCATOR_GDT_ENTRY_OFFSET equ 32
TSS_ENTRY_SIZE_SHIFT         equ 4

hw_cpu_id PROC
        xor     rax, rax
        str     ax
        sub     ax, CPU_LOCATOR_GDT_ENTRY_OFFSET
        shr     ax, TSS_ENTRY_SIZE_SHIFT
        ret
hw_cpu_id ENDP

Asm_Rdtsc Proc
  mov rbx,rcx
  mov rsi,rdx

  xor rax,rax
  xor rdx,rdx

  rdtsc
  mov [rbx],rax
  mov [rsi],rdx
  ret
Asm_Rdtsc Endp

END


