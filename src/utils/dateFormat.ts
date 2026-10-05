/**
 * Format timestamp into clean, human-readable format:
 * "DD Month YYYY, h:mm AM/PM"
 *
 * Examples:
 *   "05 October 2026, 5:18 PM"
 *   "24 September 2026, 4:39 PM"
 *   "01 November 2026, 10:05 AM"
 */
export function formatScanDate(input: string | number | Date | null | undefined): string {
  if (!input) return "05 October 2026, 5:18 PM";

  let date: Date;

  if (typeof input === "string") {
    // If string already matches "DD Month YYYY, h:mm AM/PM", return as is
    if (/^\d{2}\s+[A-Za-z]+\s+\d{4},\s+\d{1,2}:\d{2}\s+[AP]M$/.test(input.trim())) {
      return input.trim();
    }
    date = new Date(input);
  } else if (typeof input === "number") {
    date = new Date(input);
  } else {
    date = input;
  }

  if (isNaN(date.getTime())) {
    return String(input);
  }

  const months = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
  ];

  const day = String(date.getDate()).padStart(2, "0");
  const month = months[date.getMonth()];
  const year = date.getFullYear();

  let hours = date.getHours();
  const ampm = hours >= 12 ? "PM" : "AM";
  hours = hours % 12;
  hours = hours ? hours : 12;
  const minutes = String(date.getMinutes()).padStart(2, "0");

  return `${day} ${month} ${year}, ${hours}:${minutes} ${ampm}`;
}
