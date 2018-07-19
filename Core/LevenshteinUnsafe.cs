using System;
using System.Collections.Generic;
using System.Text;

namespace IPBan
{
    /// <summary>
    /// Measures the difference between two strings.
    /// Uses the Levenshtein string difference algorithm.
    /// </summary>
    public static class LevenshteinUnsafe
    {
        /// <summary>
        /// Compares the two values to find the minimum Levenshtein distance. 
        /// Thread safe.
        /// </summary>
        /// <returns>Difference. 0 complete match. -1 if either value1 or value2 is null, -2 if value2 is too large.</returns>
        public static unsafe int Distance(string value1, string value2)
        {
            if (value1 == null || value2 == null)
            {
                return -1;
            }
            else if (value2.Length == 0)
            {
                return value1.Length;
            }
            else if (value1.Length == 0)
            {
                return value2.Length;
            }

            int* costs = stackalloc int[value2.Length];
            int* costsEnd = costs + value2.Length, ptr;
            int i = 0, j, insertionCost, cost, additionCost;
            char value1Char;

            for (ptr = costs; ptr != costsEnd; ptr++)
            {
                *ptr = ++i;
            }

            for (i = 0; i < value1.Length; i++)
            {
                // cost of the first index
                cost = additionCost = i;

                // cache value for inner loop to avoid index lookup and bounds checking, profiled this is quicker
                value1Char = value1[i];

                for (ptr = costs, j = 0; ptr != costsEnd; ptr++, j++)
                {
                    insertionCost = cost;
                    cost = additionCost;

                    // assigning this here reduces the array reads we do, improvement of the old version
                    additionCost = *ptr;

                    if (value1Char != value2[j])
                    {
                        if (insertionCost < cost)
                        {
                            cost = insertionCost;
                        }

                        if (additionCost < cost)
                        {
                            cost = additionCost;
                        }

                        ++cost;
                    }

                    *ptr = cost;
                }
            }

            // the last int is the cost
            return *(--costsEnd);
        }
    }
}
