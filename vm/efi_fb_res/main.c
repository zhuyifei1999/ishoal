#include <efi.h>
#include <efilib.h>

EFI_STATUS EFIAPI
efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
	InitializeLib(ImageHandle, SystemTable);

	EFI_STATUS Status;

	DEBUG((D_INIT, "IShoal EFI Framebuffer Mode Setter...\n"));

	EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput = NULL;
	Status = LibLocateProtocol(&GraphicsOutputProtocol, (VOID **)&GraphicsOutput);
	if (EFI_ERROR(Status) || !GraphicsOutput)
		goto out;

	DEBUG((D_INFO, "Current Mode: %d\n", GraphicsOutput->Mode->Mode));

	INT32 SetModeNumber = -1;
	for (INT32 ModeNumber = 0; ModeNumber < GraphicsOutput->Mode->MaxMode; ModeNumber++) {
		UINTN SizeOfInfo;
		EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
		Status = uefi_call_wrapper(GraphicsOutput->QueryMode, 4,
					   GraphicsOutput, ModeNumber,
					   &SizeOfInfo, &Info);
		if (EFI_ERROR(Status))
			continue;

		DEBUG((D_INFO, "Mode %d, %dx%d\n", ModeNumber,
		      Info->HorizontalResolution, Info->VerticalResolution));

		if (Info->HorizontalResolution == 640 &&
		    Info->VerticalResolution == 480)
			SetModeNumber = ModeNumber;
	}

	if (SetModeNumber >= 0) {
		uefi_call_wrapper(GraphicsOutput->SetMode, 2,
				  GraphicsOutput, SetModeNumber);

		DEBUG((D_INFO, "New Mode: %d\n", GraphicsOutput->Mode->Mode));
	}

out:;
	EFI_LOADED_IMAGE *LoadedImage;
	Status = uefi_call_wrapper(BS->HandleProtocol, 3,
				   ImageHandle,
				   &LoadedImageProtocol,
				   (VOID **)&LoadedImage);
	if (EFI_ERROR(Status))
		return Status;

	EFI_DEVICE_PATH *Path = FileDevicePath(LoadedImage->DeviceHandle, L"\\linux.efi");
	if (!Path)
		return EFI_INVALID_PARAMETER;

	EFI_HANDLE LinuxHandle;
	Status = uefi_call_wrapper(BS->LoadImage, 6, FALSE, ImageHandle,
				   Path, NULL, 0, &LinuxHandle);
	if (EFI_ERROR(Status))
		return Status;

	return uefi_call_wrapper(BS->StartImage, 3, LinuxHandle, NULL, NULL);
}
