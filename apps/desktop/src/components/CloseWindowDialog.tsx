import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";

interface Props {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onQuit: (remember: boolean) => void;
  onMinimize: (remember: boolean) => void;
}

export function CloseWindowDialog(p: Props) {
  const { t } = useTranslation();
  const [remember, setRemember] = useState(false);
  // Reset the checkbox whenever the dialog is dismissed so it never carries over.
  const onOpenChange = (o: boolean) => {
    if (!o) setRemember(false);
    p.onOpenChange(o);
  };
  return (
    <Sheet open={p.open} onOpenChange={onOpenChange}>
      <SheetContent side="bottom" className="bg-panel border-border rounded-t-2xl">
        <SheetHeader><SheetTitle>{t("close_dialog.title")}</SheetTitle></SheetHeader>
        <div className="px-4 pb-6">
          <p className="text-[13px] leading-relaxed text-foreground/90">{t("close_dialog.body")}</p>
          <div className="mt-4 flex items-center justify-between border-y border-border py-3">
            <Label className="text-[13px]">{t("close_dialog.remember")}</Label>
            <Switch checked={remember} onCheckedChange={setRemember} />
          </div>
          <div className="mt-5 flex gap-2">
            <Button variant="ghost" className="flex-1 text-dim" onClick={() => p.onMinimize(remember)}>
              {t("close_dialog.minimize")}
            </Button>
            <Button className="flex-1 bg-wisp text-bg0 hover:bg-wisp-bright" onClick={() => p.onQuit(remember)}>
              {t("close_dialog.quit")}
            </Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
