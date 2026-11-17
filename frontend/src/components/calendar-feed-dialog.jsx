/**
 * Dialog that shows the absolute ICS calendar-feed URL (including the
 * per-install ?token=), with copy and regenerate actions.
 */
import { useMemo, useState } from "react";
import { CopyIcon, RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogPanel,
  DialogPopup,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { toastManager } from "@/components/ui/toast";
import { useCalendarToken, useRegenerateCalendarToken } from "@/hooks/use-api";
import { buildFeedUrl } from "@/lib/calendar-range";

/**
 * @param {{filters?: Record<string,string>, children?: import("react").ReactNode}} props
 *   `filters` are extra query params for the feed; children is the trigger label.
 * @returns {JSX.Element} Trigger button plus dialog.
 */
export function CalendarFeedDialog({ filters, children }) {
  const [isOpen, setIsOpen] = useState(false);
  const { data, isLoading, isError } = useCalendarToken();
  const regenerate = useRegenerateCalendarToken();
  const feedUrl = useMemo(
    () => (data?.token ? buildFeedUrl(window.location.origin, data.token, filters) : ""),
    [data?.token, filters],
  );

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(feedUrl);
      toastManager.add({ type: "success", title: "Feed URL copied" });
    } catch {
      toastManager.add({ type: "error", title: "Could not copy", description: "Select the URL and copy it manually." });
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger render={<Button variant="outline" size="sm" />}>
        {children}
      </DialogTrigger>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle>Calendar feed</DialogTitle>
          <DialogDescription>
            Subscribe to this iCalendar URL in your calendar app. Anyone with the
            URL can read your schedule, so keep it private.
          </DialogDescription>
        </DialogHeader>
        <DialogPanel className="space-y-3">
          <Input
            readOnly
            aria-label="Calendar feed URL"
            value={isLoading ? "Loading..." : isError ? "Failed to load feed URL" : feedUrl}
            onFocus={(e) => e.target.select()}
          />
        </DialogPanel>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => regenerate.mutate()}
            loading={regenerate.isPending}
          >
            <RefreshCwIcon className="size-4" />
            Regenerate
          </Button>
          <Button onClick={handleCopy} disabled={!feedUrl}>
            <CopyIcon className="size-4" />
            Copy URL
          </Button>
        </DialogFooter>
      </DialogPopup>
    </Dialog>
  );
}
