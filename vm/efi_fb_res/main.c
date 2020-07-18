#include <efi.h>
#include <efilib.h>

#if 0
static VOID
Sleep(UINTN Microseconds)
{
	uefi_call_wrapper(BS->Stall, 1, Microseconds);
}
#else
#define Print(...) do {} while (0);
#define Sleep(...) do {} while (0);
#endif

static EFI_GUID GraphicsOutputProtocolGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;


EFI_STATUS EFIAPI
efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
	InitializeLib(ImageHandle, SystemTable);

	EFI_STATUS Status;

	Print(L"IShoal EFI Framebuffer Mode Setter...\r\n");

	EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput = NULL;
	Status = uefi_call_wrapper(BS->LocateProtocol, 3,
				   &GraphicsOutputProtocolGuid,
				   NULL, (VOID **)&GraphicsOutput);
	if (Status != EFI_SUCCESS || !GraphicsOutput)
		goto out;

	Print(L"Current Mode: %d\r\n", GraphicsOutput->Mode->Mode);

	INT32 SetModeNumber = -1;
	for (INT32 ModeNumber = 0; ModeNumber < GraphicsOutput->Mode->MaxMode; ModeNumber++) {
		UINTN SizeOfInfo;
		EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
		Status = uefi_call_wrapper(GraphicsOutput->QueryMode, 4,
					   GraphicsOutput, ModeNumber,
					   &SizeOfInfo, &Info);
		if (Status != EFI_SUCCESS)
			continue;

		Print(L"Mode %d, %dx%d\r\n", ModeNumber,
		      Info->HorizontalResolution, Info->VerticalResolution);

		if (Info->HorizontalResolution == 640 &&
		    Info->VerticalResolution == 480)
			SetModeNumber = ModeNumber;
	}

	Sleep(5 * 1000 * 1000);

	if (SetModeNumber >= 0) {
		uefi_call_wrapper(GraphicsOutput->SetMode, 2,
				  GraphicsOutput, SetModeNumber);

		Print(L"New Mode: %d\r\n", GraphicsOutput->Mode->Mode);
	}

out:
	Sleep(5 * 1000 * 1000);

	EFI_LOADED_IMAGE *LoadedImage;
	Status = uefi_call_wrapper(BS->OpenProtocol, 6, ImageHandle,
				   &LoadedImageProtocol, (VOID **)&LoadedImage,
				   ImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (Status != EFI_SUCCESS)
		return Status;

	EFI_DEVICE_PATH *Path = FileDevicePath(LoadedImage->DeviceHandle, L"\\linux.efi");
	if (!Path)
		return EFI_INVALID_PARAMETER;

	EFI_HANDLE LinuxHandle;
	Status = uefi_call_wrapper(BS->LoadImage, 6, FALSE, ImageHandle,
				   Path, NULL, 0, &LinuxHandle);
	if (Status != EFI_SUCCESS)
		return Status;

	return uefi_call_wrapper(BS->StartImage, 3, LinuxHandle, NULL, NULL);
}
