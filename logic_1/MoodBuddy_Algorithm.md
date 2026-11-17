# MoodBuddy algorithm

Algorithm for the MoodBuddy mood tracker ([`MoodBuddy.py`](MoodBuddy.py)). The flowchart version is
[`MoodBuddy_Algorithm_Flowchart.png`](MoodBuddy_Algorithm_Flowchart.png) (made in Figma).

1. Start program
2. Display welcome message
3. Prompt user for Name
4. Is Name valid (non-blank, ≤20 letters, no spaces/numbers/symbols)?
   - No → go to Step 3
5. Prompt user for Age
6. Is Age a valid number between 4 and 100?
   - No → go to Step 5
7. Is Age between 66 and 100?
   - Yes → display standard message
8. Determine age range for the entered age
9. Check if (Name + Age) exists in saved data file
   - Yes → load saved emotion counters
   - No → create new record, all counters = 0
10. Ask "How is your mood today?"
11. Match input to an emotion
12. Is the emotion negative (Sad/Angry/Anxious) or non-negative (Happy/Excited/Lazy)?

   **If non-negative:**

   - 13a. Reset all three negative counters (Sad, Angry, Anxious) to 0
   - 14a. Randomly pick one of the 4 messages for (emotion + age range)
   - 15a. Get one activity for that emotion
   - 16a. Display message + activity → go to Step 19

   **If negative:**

   - 13b. Increment that emotion's counter
   - 14b. Is counter = 1? → Select message 1
   - 15b. Is counter = 2? → Select message 2
   - 16b. Is counter ≥ 3? → Select message 3 (or message 4, if counter ≥ 4), together with the warning message for that emotion
   - 17b. Get one activity for that emotion
   - 18b. Display selected message(s) + activity → go to Step 19

19. Save updated data (counters, name, age) back to file
20. Ask "Do you want to check in again or quit?"
    - Continue → go to Step 10
    - Quit → go to Step 21
21. Display goodbye message ("See you soon!")
22. End program
